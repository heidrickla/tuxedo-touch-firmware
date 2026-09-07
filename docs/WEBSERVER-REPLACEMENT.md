# WEBSERVER-REPLACEMENT.md

Replacing the Barracuda web/TLS layer with a server built from scratch.

Status: design. Nothing in this document has been built. Every claim carries an
evidence label: **MEASURED** (run against the live panel or a built binary),
**READ** (traced in a binary, a config file or source), **INFERRED** (reasoned
from the above). Where a mapping pass was adversarially reviewed and the review
won, the corrected claim is the one used here and the original is kept next to
it.

---

## 0. Scope in one paragraph

`/tuxedo` stays. `Barracuda` goes, in full: HTTP, TLS, sessions, the REST
facade, `/handlerequest*.html`, the push stream, and the 27 compiled web pages.
The replacement is a single static Rust binary talking to `/tuxedo` over the two
POSIX message queues that already are the boundary. The migration is staged so
that the panel can arm and disarm at the end of every stage, and every stage
reverts with a file move and a process restart.

---

## 1. What we keep and why

### 1.1 We keep `/tuxedo`, permanently

`/tuxedo` is the ECP protocol implementation against the VISTA-21iP. That is not
a figure of speech about it being complicated; it is what the binary is.

- 12,592 symbols, 10,585 of them `STT_FUNC`, unstripped `.symtab`. **READ**
- It owns the CAL layer (`CALExplicitInvokeManager`), the panel state machine,
  the arming/bypass/zone/event-log logic, the user-code authority model, the
  88-signal touchscreen UI dispatch table at `0x80574`, and the Qt UI itself.
  **READ**
- ECP is Honeywell's proprietary keypad bus. There is no specification. The only
  way to reimplement it is to drive a live VISTA-21iP and observe, and a wrong
  frame on that bus is a fault condition or a false alarm on somebody's house.

Rewriting `/tuxedo` would mean reimplementing an undocumented realtime bus
protocol, with no test rig, against a device whose failure mode is the fire
department. It is out of scope now and it stays out of scope.

**Consequence for everything below:** the replacement server is a *client* of
the alarm application. It never touches ECP. If the replacement dies, `/tuxedo`
keeps arming and disarming from the touchscreen — the only thing lost is the web
interface. That property is what makes the whole plan safe, and it is
load-bearing:

> `tuxedo`'s `osal_MqSend` @`0x5a78e0` reads `mq_attr`, and when
> `mq_curmsgs == mq_maxmsg` it calls `osal_MqFlush` and sends anyway. It does not
> block on a full queue. **READ**, reproduced independently by the review.

Scope note the review is right about: that is a statement about one send helper
covering 204 call sites, not a proof that `/tuxedo` never waits on the web server
anywhere. "A dead web server cannot stall the alarm application" is **INFERRED**,
not measured, and stage 6 is designed to test it rather than assume it.

### 1.2 We keep `supervis`, and we satisfy it rather than fight it

`supervis` is the sole `/dev/watchdog` kicker. **READ** — `wdg_init` @`0xb590`
opens `/dev/watchdog` and arms a software timer whose handler
`WdgKickHndlr` @`0xb4e4` issues `ioctl(fd, 0x7403 /* WDIOC_KEEPALIVE */)`.
Nothing else on the box has a watchdog symbol. **MEASURED**: `/proc/903/fd/4`,
`/proc/1095/fd/4` and `/proc/1127/fd/4` all point at `/dev/watchdog`, same fd
number, consistent with inheritance across `supervis`'s `system()` fork.

Killing or patching out `supervis` costs the watchdog. Do not.

What `supervis` does to the web server, in the corrected form:

- It finds processes by `strcmp` against the `comm` field of `/proc/<pid>/stat`
  (`getProcessPid` @`0xbeb0` → `processdir` @`0xbd68`). Not by path, not by pid.
  **READ**
- `SupervisTimeout` @`0xca04`: if `getProcessPid("Barracuda")` returns 0, or the
  process exists but `get_num_fds > 800` (`cmp r0,#0x320`), it calls
  `relaunchBarracuda`. **READ**
- `launchBarracuda` @`0xc31c` = `apl_killProcess("Barracuda")` then
  `system("/opt/webserver/Barracuda &")`, where `apl_killProcess` @`0xbf78` is
  `kill(getProcessPid(name), 9)`. **READ**
- After 24 relaunches (`cmp r3,#0x18` in `main` @`0xc684`) it logs *Webserver
  reached max relaunches. Restarting the Tuxedo* and calls
  `DisArmSWTimer` on the timer created by `wdg_init`. **READ**

**Correction the review made, and it inverts the operational consequence:** the
timer disarmed at the 24-relaunch ceiling is the *watchdog keepalive*, not a
supervision timer. Hitting the ceiling means the watchdog stops being kicked and
the unit resets. A replacement that crash-loops does not get quietly left alone;
it reboots the panel.

**Second correction:** a differently-named replacement is *not* killed —
`apl_killProcess("Barracuda")` resolves by `comm` and never signals it. What
actually happens is that `supervis` sees no Barracuda, starts the vendor binary
every poll, the vendor collides on the already-bound ports, and the counter
climbs to 24. Same destination, different mechanism.

Design rules that fall out, all mandatory:

1. The replacement is installed at `/opt/webserver/Barracuda`, so its `comm` is
   `Barracuda` (basename, ≤ 15 chars — kernel behaviour, **INFERRED**, cheap to
   confirm, see §5.4).
2. It holds fewer than 800 fds, always. Bounded connection pool, hard cap.
3. It never crash-loops. On any startup failure it `execve`s the vendor binary
   (§4.6), so `supervis` sees a healthy `Barracuda` and the counter never climbs.
4. It does not touch inherited fd 4.

`supervis` also carries an arbitrary-root-command primitive on message ID 21 of
`/g_mqSupervisionThreadIn`, not reachable from its TCP socket
(`SERVICES-6800-9443.md`, single-source). Not used, not relied on, noted so the
threat model in `tls/THREAT-MODEL.md` can say so.

### 1.3 We keep the message-queue contract as the ABI

This is the piece that makes replacement tractable, and it is the best-evidenced
thing in the project.

**The command queue** — `/Q_ServCmdRcver`, msgsize `0x194` (404), maxmsg 32,
client → tuxedo. **READ** from both sides (`createServer` @`0xce78` in Barracuda;
`CReceiverThread` ctor @`0x141708` in tuxedo).

**The reply queue** — `/Q_ServCmdTrsmtr`, msgsize `0x22c` (556), maxmsg 32,
tuxedo → client. **READ**, same sources.

Command struct, fixed header, then a per-band union. `web_request` is the
vendor's own type name (60+ slot signatures in tuxedo's symtab take
`web_request*`). **READ**

```
+0x00 u32 sessionId
+0x04 u32 command
+0x08 .. per-band union:
      security (1-10,13-16,18,25-29,500-503): +0x08 partition bitmask,
                                              +0x0C user code (0xFFFF = none)
      console  (19):                          +0x2E key count, +0x2F..+0x3E keys
      eventlog (17):                          +0x08 partition (0xFF = all),
                                              +0x10 filters, +0x14 index
      zwave    (100-149):                     +0x08 u16 device id, +0x0A..+0x0F
                                              bytes, +0x10 u32 (sometimes f32)
      camera   (52-58):                       +0x08 NUL-terminated string
```

Reply struct: `+0x00 u32 sessionId` (0 = broadcast), `+0x04 u32 msgType`,
`+0x08 u32 arg`, NUL-terminated display text at `+0x0E`. 43 msgTypes dispatched.
**READ**, reproduced independently by the review.

Dispatch completeness, settled at **84**: `dispatch_tree.py` walks
`CReceiverThread::run` carrying an interval and an exclusion set for the
received code and reports every block the constraints can still reach, with no
path left unresolved. The set is
`1-19, 25-27, 29, 52-58, 100, 102, 104-129, 147, 154, 300-303, 500-503, 508,
509, 601-608, 700, 800, 801, 888, 6285, 9999`. Not every one does work: 102 and
123-124 branch straight back to the receive loop, so the panel accepts them and
discards them; 100 and 116 only `puts()` their own vendor name.

The two the earlier count of 82 was missing are `6285`
(`sigsimulateTouchPoints(QPoint)`) and `9999` (`ZWaveSendHomeId`), both compared
register-to-register against a literal-pool word rather than an immediate. The
authoritative form is `commands.tsv`, regenerated from the binary.

Two facts prove the boundary is speakable by a third party:

- `/TotalConnect` (pid 1137) holds `/Q_ServCmdRcver` open. **MEASURED**
- `TCInterfaceInit` @`0x209b8` creates it with msgsize `0x11c` (284) and ten
  functions send on that fd with `r2 = 0x11c`. **READ**

**Honest downgrade the review is right about:** the *open* is measured; no
`TotalConnect` message was ever observed on the wire. "A non-Barracuda process
already speaks this protocol today" is **INFERRED** from unconditional code, not
empirical. It is strong, but it is not the proof, and §5.1 names the experiment
that would be.

### 1.4 We keep, conditionally: static assets

The embedded ZIP at `Barracuda[0x8a948:0x4f0114]` is 776 entries: 505 png, 127
css, 94 js, 20 Thumbs.db, 9 gif, 7 html, 7 jpg, 4 txt, 2 shtml, 1 mov.
**MEASURED**, histogram reproduced by the review. It contains **no application
pages** — the 27 pages are compiled C (`*_html076EF::service`) emitting ~295 KB
of `.rodata` HTML fragments interleaved with runtime substitutions. **READ**

30 of the 94 JS files read server-injected DOM ids (`hidSession`, `hiddenKey`,
`curStatus`, `var server=`). **MEASURED**

So: images and CSS carry over verbatim. The vendor JS does not, because it
depends on page shells we are not generating and on RTL's EventHandler transport
we are not implementing. The UI is a rewrite. Reuse the PNGs if they look right;
do not try to keep the app.

### 1.5 What we do not keep

| Dropped | Why |
|---|---|
| SharkSSL and the whole TLS layer | No `setCertificate` API in the build; `sharkssl_PEM_to_RSAKey` @`0x5e5cc`, `HttpSharkSslServCon_setPort` @`0x49e6c` and `HttpServCon_setPort` @`0x68610` all have zero callers and zero genuine data references. **READ**, verified twice. The cert is the RTL demo credential and the private key is in the binary. |
| `/system_http_api/API_REV01/...` | WNMP auto-documenting facade; ~45 documented paths, ~6-8 answer with data. Replaced by a new API, not reimplemented. |
| `/handlerequest.html` (99 Types) and `/handlerequest_mobile.html` | Replaced by a typed API over the same command codes. |
| RTL EventHandler push transport | Replaced. See §2.5 for what we owe `ha-tuxedo-touch`. |
| Ports 6280 and 9443 | Same handlers, same document root, same auth realm as 80/443. 9443 is a hardcoded literal (`0x24e3` in `barracuda()`'s literal pool @`0x108fc`) with no config key. **READ.** We simply do not bind them. |
| Vendor config writes | v1 writes nothing under `/opt/tuxedo/configuration` except its own new subtree. See §1.6. |
| Video, voice, camera, Z-Wave management, scenes, TotalConnect web pages | Not in v1. Later stages or dropped. Stated up front so nobody discovers it after the cutover. |

### 1.6 Configuration: we do not inherit the vendor's files

The mapping pass claimed Barracuda writes ~21 config files each guarded by a
`_sec` CRC sidecar. The review downgraded this correctly: the evidence was a
path-string scan, which proves reference, not write.
`validateCRCFileOnFileWrite` has exactly **7** callers —
`resetLoginFailureCount`, `resetLoginFailureCount1`, `updateLoginFailureCount`,
`writeRemoteTuxDevNode`, `writeSceneDetails`, `writeGroupDetailsWithDeviceList`,
`writeDeletedGroupDetails`. **READ.** The write set for everything else was never
established.

Rather than reverse-engineer a CRC scheme whose scope is unknown, v1 owns its
own state at `/opt/tuxedo/configuration/tuxweb/` and touches nothing the vendor
wrote. Consequences, stated plainly:

- Web user accounts move to our store. The vendor UI's account editor is gone
  with the vendor UI, so this is not a regression, it is a relocation.
- **This is an improvement worth taking deliberately:** on this panel the web
  password is also the panel user code (`README.md`). Our auth store is
  independent, so a web login credential stops being an arming credential. The
  panel user code is then supplied per arming action, or stored per user
  encrypted and opt-in. Either way the two secrets stop being the same secret.
- Z-Wave / scene / group / thermostat DBs stop being edited from the web. Those
  features are not in v1 anyway.
- ~~**Unknown, and it must be checked before stage 6:** whether `/tuxedo` itself
  reads `webuseraccountsenc.json`.~~ **CHECKED, 2026-09-06 (§5.6): it reads it
  and writes it.** This is now a decision rather than an unknown, and the
  decision is below.

#### What `/tuxedo` uses the account store for — and so what abandoning it costs

Every consumer, by caller (tail calls counted):

| consumer | what it is |
|---|---|
| `CAccountsSetup::readFromAccSettingsFile()` / `ApplySettings(bool)` | the **touchscreen's own account-setup screen** |
| `CInitialAccountsSetup::*` | the **first-boot account wizard** |
| `migrateAccSetupFile()`, `migrateAccSetupFileInit()` | one-time migration from the plain file to the `_enc` form |
| `get_systemdata_message` | reads the file and **counts configured accounts** — 5 slots, stride `0x64`, non-empty first byte — as a system-data field |

Nothing on the arming or ECP path touches it. So the cost of abandoning it is
exactly two things, and the first is the one that matters:

1. **The touchscreen account screens survive, because `/tuxedo` survives.** This
   is the asymmetry §1.6 glossed over: the vendor *web* UI dies with Barracuda,
   but the *on-screen* editor does not. An owner who edits accounts on the
   keypad writes a store `tuxweb` never reads. Two account databases, diverging
   silently, with no error anywhere.
2. `get_systemdata_message`'s account count goes stale.

**The format, since it decides the cost of keeping it in sync.**
`createWebUserAccSetupJSONFile` builds a JSON document with the bundled
`json_*` helpers, `json_write`s it, then `aes_init` + **`AES_ofb`** and
`fwrite`s the ciphertext. It writes `/tmp/webuseraccountsenc.json` and the
configuration copy. There is **no CRC sidecar on this path** —
`validateCRCFileOnFileWrite`'s seven callers are the login-failure and
scene/group writers, not these — so §1.6's reason for not inheriting vendor
files (an unknown CRC scheme) does not apply to this particular file.

Worth noting while we are here: the key comes from `aes_init` inside the
binary, so the `enc` in the filename is obfuscation, not protection, against
anyone holding the firmware.

**DECIDED 2026-09-06: (a) — `tuxweb` maintains the vendor file.** Keypad and web
stay one account list and the system-data count stays right. The rest of this
section is the format that decision requires, all of it verified against the
panel's real file rather than inferred from the writer.

#### The account file format

**Envelope.** AES-128 in **OFB**, no padding, so ciphertext length equals
plaintext length exactly — the panel's file is 1053 bytes of each. The call is
`AES_ofb(128, key, in, out, len, 0, iv)` and both operands are 16-byte constants
in `/tuxedo`'s `.data`:

| | address in `/tuxedo` |
|---|---|
| key | `0xd09654` |
| iv | `0xd09664` |

They are **static, compiled in, and therefore identical on every panel running
this firmware**. Deliberately not reproduced here, and `tuxweb` should not embed
them either — it should read them out of `/tuxedo` at runtime, which keeps key
material out of this repository and follows the vendor if it ever changes them.

Because they are static, `enc` in the filename is obfuscation. Anyone holding
the firmware can decrypt any panel's account file, which contains `userName`,
`passWord` and `EncNamePass` for every web user. That belongs in the threat
model, not just here.

**Two files, byte identical.** `webuseraccountsenc.json` and
`webuseraccountsenc_sec.json` had the **same md5** on the panel. `_sec` is a
mirror, **not a CRC sidecar** — which means §1.6's stated reason for not
inheriting vendor files, an unknown CRC scheme, genuinely does not apply to this
one. Writing the file means writing the same bytes twice.

**ROUND-TRIPPED AGAINST THE LIVE PANEL, 2026-09-07, without disturbing the
soak.** `tuxweb --accounts-rewrite` is a one-shot that reads the live store,
decodes it, re-encodes with our own writer to a NEW path, and refuses to
overwrite anything. Result: 1053 bytes in, 1053 out; the output decodes back to
the same five slots, all sealed, `store is consistent`; and the decrypted JSON
compares **equal as a data structure**.

**The bytes are not identical, and cannot be.** They diverge at plaintext
offset 125 because the vendor's own file is internally inconsistent in key
order — entry 0 ends `userCreatedDate, userUpdatedDate, accLockedCount,
accLockedTime, accountLocked` while entries 1-4 end `accountLocked,
accLockedTime, userCreatedDate, userUpdatedDate, accLockedCount`. Slot 0 was
written by a different code path from the rest. serde emits one declaration
order for every element, so no single field order can reproduce all five;
`accounts.rs` matches entries 1-4, which is 4 of 5 and the most achievable.
That the vendor tolerates both orders in one file is itself the proof
`/tuxedo` reads these by name.

**So a live write must be verified by decoding, never by `cmp`.** A byte
difference here is expected and is not a failure. Recorded because the obvious
next move on seeing that diff is to "fix" the field order, which would take the
match from 4 of 5 to 1 of 5.

**Schema**, recovered from `createWebUserAccSetupJSONFile` and confirmed by
decrypting the live file:

```
{"WEBUSERS": [ five entries, always five, matching the 5-slot count loop
               in get_systemdata_message ]}
```

each entry carrying exactly these ten fields:

| field | type |
|---|---|
| `u8UserId` | int |
| `userName` | string |
| `passWord` | string |
| `EncNamePass` | string |
| `status` | int |
| `accountLocked` | int |
| `accLockedTime` | int |
| `userCreatedDate` | int |
| `userUpdatedDate` | int |
| `accLockedCount` | int |

**Key order is not stable and does not matter.** In the live file entry `[0]`
orders the last five fields differently from entries `[1]`–`[4]`. The vendor is
inconsistent with itself, which is useful: it proves `/tuxedo` reads these by
name, so a writer does not have to reproduce an ordering.

#### The credential fields — SOLVED, 2026-09-06

Shapes first, measured across all five accounts in the live file:

| field | shape |
|---|---|
| `userName` | printable string |
| `passWord` | **4 hex characters** |
| `EncNamePass` | **32 hex characters** = 16 bytes |

`passWord` being four digits is the panel user code itself, stored in the clear
inside the AES envelope. That is the concrete form of `README.md`'s point that
the web password *is* the arming code — there is no second secret, and
`readUserNamePasswordFromJSON` in Barracuda `strcpy`s the field straight out to
authenticate with, which is why no password hashing is possible without breaking
the wire protocol (`KERNEL-VERDICT.md`).

`EncNamePass` is an MD5. `/tuxedo` calls `MD5String` from exactly the four
account paths — `CAccountsSetup::ApplySettings`,
`CInitialAccountsSetup::ApplySettings`, `migrateAccSetupFile`,
`migrateAccSetupFileInit` — and testing constructions against the real file
settles which one:

```
EncNamePass = md5_hex( userName.lower() + passWord )
```

**5 of 5 accounts, with all eight other candidates at 0 of 5** — including
`name+pass` without the case fold, `pass+name`, and the comma, colon and space
separated forms. Tested as a boolean per candidate; no names, codes or digests
were printed or recorded.

It cross-checks against something already known: the web login computes
`HMAC-SHA512(challenge, username.lower() + password)`. The same
`lower(name) + pass` construction appears on both sides, which is what a correct
reading should look like.

**So writing a valid entry is now fully specified:**

| field | value |
|---|---|
| `u8UserId` | 1–5, the slot |
| `userName` | as entered |
| `passWord` | the 4-digit code |
| `EncNamePass` | `md5_hex(lower(userName) + passWord)` |
| `status` | 1 for an active account |
| `accountLocked`, `accLockedTime`, `accLockedCount` | 0 |
| `userCreatedDate`, `userUpdatedDate` | integer timestamps |

Nothing about the account store is unknown any more, and option (a) is
implementable.

#### Implemented, and verified against the vendor's own file

`tuxweb/src/accounts.rs`. The key and IV are **read out of `/tuxedo` at runtime**
(`key_from_binary`, resolving the virtual addresses through the ELF program
headers rather than assuming a fixed skew) and are not embedded in the binary or
this repository. AES-OFB is written out in four lines rather than pulled from a
mode crate; the dependency would have been larger than the code.

Two commands, deliberately narrow:

```
tuxweb --accounts <tuxedo-binary> [store]          # slots, names, sealed yes/no
tuxweb --accounts-rewrite <tuxedo> <in> <out>      # decode, re-encode, to a NEW path
```

`--accounts` prints no passwords and no digests. It is a consistency check, not
a credential dumper — anyone with the firmware could write the dumper, but that
is not a reason for this repository to ship one. `--accounts-rewrite` refuses to
overwrite an existing file and never touches the live store: proving the writer
works and replacing an alarm panel's account file are separate acts, and running
them together is how a verification step locks everyone out of the web UI.

**Verified against the panel's real store**, which is the test the unit tests
cannot be:

```
/tmp/acct.enc: 1053 bytes, 5 slots
  slot 1..5   status=1 locked=0 sealed=yes   (all five)
store is consistent
```

Every stored digest was reproduced by an independent implementation in a
different language — that is what `sealed=yes` means, and it is the strongest
confirmation available that `md5(lower(name) + pass)` is the rule.

Round-tripping the real file through our own writer:

```
in 1053 bytes -> out 1053 bytes, decrypts to valid JSON
5 slots -> 5 slots, every field of every account preserved
```

**Not byte-identical, and correctly so.** The files diverge at byte 126, inside
entry 0 — exactly where the vendor's own field ordering differs from its other
four entries. Identical length, identical content, different key order. Anyone
who "fixes" this by asserting byte-identity will be encoding the vendor's
inconsistency as a requirement.

33 tests pass; the ARM cross-build is 985064 bytes, against a
`BARRACUDA_MEMORY` ceiling of ~31 MB (§5.2).

Run on the panel itself against the live store, reading the key out of the live
`/tuxedo`:

```
/opt/tuxedo/configuration/webuseraccountsenc.json: 1053 bytes, 5 slots
  slot 1..5  status=1 locked=0 sealed=yes
mirror matches
store is consistent
```

#### Authentication against the store

`Store::authenticate(name, code)` is what makes decision (a) mean something: the
list the keypad edits is the list the web authenticates against, with no second
copy to drift. It honours the vendor's own `status` and `accountLocked` fields,
compares the code in constant time, and matches usernames case-insensitively
because the digest that binds name to code is computed over the lowercased name
— the vendor already treats them that way.

Failures are typed (`NoSuchUser`, `WrongPassword`, `Disabled`, `Locked`,
`Tampered`) for the operator and **must not be distinguished to a client**:
telling "no such user" from "wrong code" apart is a user-enumeration oracle, and
on a four-digit secret that matters more than usual.

`Tampered` exists because the alternative is guessing. If the stored digest does
not match the stored name and code, someone edited the file by hand or wrote it
with a different rule; picking which field to believe would be inventing an
answer.

**The four-digit code is the real constraint, and this does not fix it.** Ten
thousand possibilities means the only thing between an attacker and an account
is how fast they may guess, so anything exposing this to a network has to
throttle. P1 removed the permanent on-disk lockout deliberately and this must
not quietly reintroduce one — the vendor's `accLockedCount`/`accountLocked` are
honoured, not extended.

#### Writing

`accounts::save` validates first, encodes once, and writes **by rename** to both
paths, mirror first and the main file last. Both readers — `/tuxedo`'s
`readWebUserAccSetupJSONFile` and Barracuda's `readUserNamePasswordFromJSON` —
open the main file directly and parse whatever is there, so a partially written
file at that path is a panel that cannot authenticate anyone. Rename makes the
swap atomic; mirror-first means an interruption never leaves the mirror behind
the file it mirrors.

**Not yet done, and deliberately:** nothing has written to the live account
store. The read, authenticate, round-trip and save paths are all proven — save
against temporary paths, the rest against the panel's real file — but replacing
the panel's actual account file is a separate, owner-approved step.

### 1.7 The blockers the IPC mapping found, and which one reshapes the plan

None of these is fatal. One of them changes the shape of the migration, and it
is the reason section 4 looks the way it does.

**B1 — POSIX mqueue delivers each message to exactly one reader.** A replacement
cannot read `/Q_ServCmdTrsmtr` while Barracuda is running; they would split the
reply stream and each would see roughly half the events, with no error anywhere.
**READ** (POSIX semantics) + **READ** (Barracuda's `gettuxedoIPCCommFunc`
@`0xd5d0` is its sole `osal_MqRecv` caller on that queue).

> **This forbids the obvious migration.** There is no dual-stack cutover at the
> IPC layer — no "run both and move endpoints across one at a time". The read
> path is all-or-nothing. So the gradualism has to happen one layer up, at HTTP:
> the new server first runs as a TLS reverse proxy *in front of* Barracuda
> (stages 3-4), and only later takes the queues (stage 6). That is the single
> largest structural consequence of the mapping, and the plan is built around it.

**B2 — process identity is load-bearing.** §1.2. Install as
`/opt/webserver/Barracuda`.

**B3 — root is mandatory, twice over.** Queues are `-rwxr-x--- root root`
(**MEASURED**, `ls -la /dev/mq/`, 51 queues) and `maxmsg 32` exceeds
`/proc/sys/fs/mqueue/msg_max` = 10 (**MEASURED**), which needs
`CAP_SYS_RESOURCE`. There is no unprivileged path onto this bus. The replacement
runs as root and the threat model says so; dropping privileges is not available.

**B4 — queue geometry is fixed by whoever creates first, for the boot.**
`tuxedo` and `TotalConnect` open `O_CREAT` without `O_EXCL` (`mov r1,#0x42`),
Barracuda uses `O_RDWR|O_CREAT|O_EXCL` (`0xc2`) and falls back to plain `O_RDWR`
on `EEXIST`. `mq_open` ignores the attr struct on an existing queue. **READ.**
If a replacement started before `/tuxedo` and created the queue with wrong
attributes, `tuxedo` would adopt it and 404-byte sends would fail `EMSGSIZE`,
presenting as "commands are ignored". Mitigation: the replacement **never
creates**. It opens `O_RDWR` only, and if the queue does not exist it waits and
logs, because a missing queue means `/tuxedo` has not started yet. The startup
script already orders this: `mkdir /dev/mq; mount -t mqueue none /dev/mq;
rm -f /dev/mq/*`, then `/supervis`, then `sleep 2`, then `/tuxedo &`
(**MEASURED**, `/etc/rc.d/init.d/startup`; the Barracuda line in that script is
commented out — `supervis` starts it).

**B5 — both `osal_MqSend` implementations flush the entire queue when full**
rather than blocking or failing. **READ**, both binaries, reproduced by the
review. A reader that falls behind does not lag, it loses all 32 pending
messages silently. The reader thread does nothing but `mq_receive` into a ring
and hand off; all parsing, formatting and I/O happen on another thread.

**B6 — the push stream is not a tappable feed.** It is produced inside
Barracuda: `gettuxedoIPCCommFunc` reads the 556-byte replies and formats them
into `SimpleDebugger_vprintf` via `bprintf`/`bflush`. The stream *is* the
SimpleDebugger trace channel, which is why it needs no credential. **READ.** The
measured frame `0:21:1:fe:<0xFE>1Ready To Arm:2` is reproduced field-for-field by
the msgType-21 handler @`0xda80` with format `'%d%s%d%s%d%s%x%s%s%s%d'`. So
replacing Barracuda means reimplementing the reply→text layer, and only 7 of the
43 msgTypes are decoded past `+0x0E`.

**B7 — the reply side is single-client by construction.** Command 500 sets
`clients_connected` @`0xd2f268` to 1 and calls `registerclient` @`0x13c2f8`,
whose first act is `osal_MqFlush` on the reply queue — draining all 32 slots.
`clients_connected` and `F7_Mesgs_enabled` are single bytes, not counters.
**READ.** Fan-out to multiple web clients is our job, not the panel's.

**B8 — "exactly two queues" was wrong.** The review re-ran the fd walk and found
`/proc/923` (tuxedo) holds three of the four queues the mapping attributed to
other processes: `/g_mqSupervisionThreadIn`, `/Q_VoiceTux` and
`/mq_TuxAppVidRecEvent`. **MEASURED.** Direction was not established for all of
them, and an fd listing cannot show read vs write intent (every one of these fds
is `flags: 02` = `O_RDWR`, **MEASURED**). Operating rule, conservative:

> The replacement **opens** only `/Q_ServCmdRcver` and `/Q_ServCmdTrsmtr`, and
> **receives** only on `/Q_ServCmdTrsmtr`. It does not open, and above all does
> not receive on, any other queue. `/g_mqSupervisionThreadIn` is not needed:
> Barracuda's only sender on it is `sigHandler`
> (`Barracuda_sendMsgToSuperVisionThread` @`0xc7f0` has exactly one caller,
> **READ**), so the web server does not heartbeat and never did.

---

## 2. The target architecture

### 2.1 Runtime: Rust, static, musl

**The justification is "it was proven to run unpatched", and nothing else.**

- Rust std 1.98.1 runs on the panel, both `arm-unknown-linux-musleabi` and
  `arm-unknown-linux-musleabihf`, statically linked, no `INTERP`. Instant and
  monotonic clocks, `SystemTime`, 16 threads, HashMap/RandomState, file I/O, TCP
  accept/echo, server thread: all ok. **MEASURED**
- `rustls` 0.23.43 with the `ring` 0.17.14 provider builds for ARMv6 and
  completes TLS 1.3 handshakes on ARM1136 with no `SIGILL`. **MEASURED**, and
  **re-verified independently on the live panel 2026-09-06** by pushing the
  built probe to `/tmp` and running it. Since the whole architecture rests on
  this one claim, it was checked rather than taken on the label:

  ```
  ring provider ok, 9 cipher suites
  FULL (resumption OFF)  mean 111.24ms   9.0 conn/sec  TLSv1_3 TLS13_AES_256_GCM_SHA384
  with resumption ON     mean  26.36ms  37.9 conn/sec  TLSv1_3 TLS13_AES_256_GCM_SHA384
  RSS after std init: 220 KB      RSS at exit: 1084 KB (peak 1160 KB)
  RESULT: ALL OK   exit=0
  ```

  Both client and server ran on this CPU simultaneously, so the per-side cost is
  lower than shown. **~1.1 MB peak RSS on a 126 MB box, and 38 resumed
  handshakes/sec, is comfortably enough for a keypad's web interface.** The probe
  was removed from `/tmp` afterwards.
- Go 1.17-1.19 run stock. Go 1.20 through 1.27.1 crash at startup with
  `runtime: netpoll failed`, because this ARM syscall table stops at 363 and
  `epoll_pwait` (346) is absent inside that range. **MEASURED**, and confirmed by
  a second route: `/proc/kallsyms` shows `sys_epoll_pwait` as a weak alias at the
  same address as `sys_ni_syscall`.
- Making modern Go work needs **three** patches to the toolchain — the epoll
  constant, the deleted ARM `accept4`→`accept` fallback, and
  `syscall.Accept` being literally `Accept4(fd,0)`. Patched, Go 1.27.1 works
  completely, including a `net/http` HTTPS server reachable over the LAN.
  **MEASURED**

So both work. Rust wins because it requires no toolchain fork. A vendored,
patched GOROOT is a permanent maintenance liability on a project whose whole
premise is that upstream keeps removing the compatibility this kernel needs — Go
already broke it three separate ways in one release cycle, and the second break
presents as `i/o timeout`, not a crash.

**What is deliberately *not* part of the justification**, because the review is
right that it was not controlled:

- The handshake ranking (rustls 105 ms / Go 160 ms / mbedTLS 356 ms loopback) did
  not pin the key-exchange group. Go 1.24+ defaults to the `X25519MLKEM768`
  hybrid when `CurvePreferences` is nil, and mbedTLS's default order puts x25519
  first, which its own benchmark measures as its slowest group. The numbers are
  real; the ranking is not attributable.
- The "5x leaner" RSS and binary-size comparison put Go's full `net/http` stack
  against a ~30-line Rust TLS socket that emits a fixed HTTP-shaped string. Rust
  is very likely leaner. Not by that factor, and 1.12 MB is not the size of a
  Rust HTTPS server with equivalent function.
- "Server-side handshake ~24 ms" was `curl`'s `time_appconnect` from a Windows
  host: it includes DNS, TCP connect, two round trips and all client-side crypto.
  Not a server-side CPU measurement.

Target triple: pin one and put it in CI. `arm-unknown-linux-musleabi`
(soft-float ABI) is the conservative pick; `musleabihf` was equally verified and
the panel has VFP. The choice is not load-bearing for a static binary that does
almost no floating-point work. Note `armv6-unknown-linux-musleabihf` is **not** a
rustc target — that name is a build-failure trap.

Per `TRAPS.md` section 6: anything that must work at boot gets executed under
`qemu-user` in a chroot of the extracted rootfs, with `/dev` exactly as the image
ships it, before it goes into an image.

### 2.1b The build toolchain, set up and proven 2026-09-06

On the build VM (`claude@203.0.113.40`, key `~/.ssh/fwbuild_ed25519`):

```bash
export RUSTUP_HOME=/build/rt/rustup CARGO_HOME=/build/rt/cargo
export PATH=$CARGO_HOME/bin:$PATH
# rustup, minimal profile, no PATH modification
rustup target add arm-unknown-linux-musleabi
```

**The target is `arm-unknown-linux-musleabi`.** `armv6-unknown-linux-musleabihf`
does not exist as a rustc target — confirmed by `rustup target list`, which
offers only `arm-*` and `armv7-*`. Guessing the armv6 name is a documented trap
and it is real.

`.cargo/config.toml` for the crate:

```toml
[target.arm-unknown-linux-musleabi]
linker = "rust-lld"
rustflags = ["-C","link-self-contained=yes","-C","target-feature=+crt-static"]
```

**Correction:** an earlier version of this line said no cross-C-toolchain is
needed. That is true only for pure Rust. **`ring` compiles C**, so a cross
compiler IS required, and `cc-rs` looks for `arm-linux-musleabi-gcc`, which does
not exist on Ubuntu. Point it at the soft-float gnu one — `gnueabi`, not
`gnueabihf`, to match the `musleabi` target:

```bash
export CC_arm_unknown_linux_musleabi=arm-linux-gnueabi-gcc
export AR_arm_unknown_linux_musleabi=arm-linux-gnueabi-ar
```

Linking is still `rust-lld` with `link-self-contained`, so the gnu toolchain only
compiles ring's C and nothing gnu is linked into the result.

**Proven end to end, not assumed.** A smoke-test crate built on the VM
(392,780 bytes, `ELF 32-bit LSB executable, ARM, EABI5, statically linked,
stripped`) was pushed to the panel and run:

```
tuxweb smoke: arch=arm pid=1899
bound 127.0.0.1:46202
threads: Ok(1)
OK   exit=0
```

So the loop is closed: write Rust on the workstation, build on the VM, run on
2.6.31/ARM1136. Note `available_parallelism()` reports **1** — the panel is
single-core, so the server should not size pools by CPU count.

Rust 1.98.1, the same version the rustls TLS 1.3 probe was built and verified
with (§2.1).

### 2.1c Stage 3 RUNNING ON THE PANEL, 2026-09-06

`tuxweb/` in this repo is a TLS listener that was built, deployed to a spare
port alongside Barracuda, and connected to. **This is no longer a design.**

Panel side:

```
tuxweb: 2 certificate(s) from chain.pem
tuxweb: listening on 0.0.0.0:8443
tuxweb: ready
```

Client side, verifying against the owner CA generated by `tls/tuxedo-ca.py`:

```
version   TLSv1.3
cipher    TLS_AES_256_GCM_SHA384
subject   CN=203.0.113.5
SAN       IP Address 203.0.113.5
notAfter  Oct  8 15:17:27 2027 GMT
body      tuxweb stage 3 / protocol TLSv1_3 / cipher TLS13_AES_256_GCM_SHA384
```

A negative control with the CA untrusted was **correctly rejected**
(`self-signed certificate in certificate chain`), so the handshake is really
being validated rather than waved through.

**839 KB static ARM binary, TLS 1.3, on a 2009 kernel, with a certificate whose
private key never touched the panel.** It ran alongside Barracuda without
disturbing it — 5 listeners before, 5 after, all five vendor processes healthy —
which is the whole point of doing this on a spare port first.

Deliberately single-threaded: `available_parallelism()` reports **1**, so a pool
sized by CPU count would be one thread pretending to be several.

Stopped and removed after the test; nothing was left listening on the panel.

### 2.2 TLS

`rustls` 0.23 + `ring`. TLS 1.3 preferred, TLS 1.2 floor, ECDHE only, no static
RSA, no plain DH. AES-GCM and ChaCha20-Poly1305. Session resumption **on** —
measured 105 ms full versus 26 ms resumed on this CPU, a 4x saving, replicated
3x. **MEASURED**

ECDSA P-256 server key. The measurement is `rsa 2048 sign 0.189375 s` versus
`ecdsa nistp256 sign 0.0043 s` on the panel's own OpenSSL 1.0.1h — a 44x ratio.
**MEASURED.** The key-type *decision* is **INFERRED** from that ratio; the
handshake budgets derived from it (21.5 ms vs 206 ms) are arithmetic on two
benchmark lines, not measured handshakes.

Bulk-transfer preference is ChaCha20: this CPU has no AES instructions
(`/proc/cpuinfo Features = swp half thumb fastmult vfp edsp java`, **MEASURED**)
and C AES-GCM runs at 2073 KiB/s against ChaCha20 at 15,849 KiB/s. **MEASURED**

**What the current endpoint actually fails on, corrected.** The mapping said
"unreachable because it omits RFC 5746 `renegotiation_info`". The review
measured past that: with `-legacy_server_connect` the handshake proceeds, the
certificate *is* evaluated, and it then fails independently on `dh key too small`
(1024-bit DHE) and `EE certificate key too weak` (1024-bit RSA), on top of
expiry. Missing RI is the first of at least three blockers, not the cause. And
the endpoint does speak **TLS 1.2** — `DHE-RSA-AES256-SHA256`,
`rsa_pkcs1_sha256`; the earlier "TLS 1.0 only" result came from forcing `-tls1`.
**MEASURED.** Any doc line saying this stack cannot do TLS 1.2 is wrong.

**Why we bring our own stack.** `/usr/sbin/openssl` is 1.0.1h (June 2014) and
links `/lib/libssl.so.1.0.0` and `/lib/libcrypto.so.1.0.0`; `openssl ciphers -v |
grep -c TLSv1.2` returns 28, including `ECDHE-ECDSA-AES256-GCM-SHA384`.
**MEASURED.** So the shipped library *does* do TLS 1.2 with ECDHE and AES-GCM —
the SONAME `1.0.0` spans the whole 1.0.x line and proves nothing about the
branch. That earlier claim was wrong and is retracted here. The exclusion stands
on the real grounds: eleven years of CVEs, long EOL, and no reason to link a
network-facing 2014 TLS stack when a current one builds statically.

### 2.3 Process and identity

```
/opt/webserver/Barracuda            the replacement (comm = "Barracuda")
/opt/webserver/vendor/Barracuda     the vendor binary, basename preserved
```

The vendor copy keeps the basename deliberately: after `execve`, `comm` becomes
the new basename, so a fallback exec into `vendor/Barracuda` still satisfies
`supervis`. Putting it at `Barracuda.vendor` would silently break the safety net.

Startup contract:

1. Wait for `/Q_ServCmdRcver` and `/Q_ServCmdTrsmtr` to exist. Never create.
2. Open both `O_RDWR`. Set `FD_CLOEXEC` on everything we open, so a fallback
   `execve` drops them cleanly for the vendor to re-open.
3. Do not touch inherited fd 4 (`/dev/watchdog`). Never write `V` to it. Our copy
   is a duplicate of `supervis`'s open file description; closing ours does not
   close `supervis`'s, but there is no reason to go near it.
4. Bind 80 and 443. Hard cap on concurrent connections; total fds monitored and
   kept far below 800.
5. On any failure in 1-4 within the startup window: close listeners and
   `execve("/opt/webserver/vendor/Barracuda", ...)`.

### 2.4 Diagram

```
                              LAN
                               |
              +----------------+----------------+
              |                                 |
        :80  301 only                     :443  TLS 1.3 (rustls+ring)
              |                                 |
              +----------------+----------------+
                               |
   +===========================================================+
   |  tuxweb   Rust, static musl, installed as                 |
   |           /opt/webserver/Barracuda   comm="Barracuda"     |
   |                                                           |
   |   tls     rustls 0.23 / ring 0.17, ECDSA P-256, resume on |
   |   auth    sessions + per-client push tokens (own store)   |
   |   http    new JSON API  +  legacy push shim (see 2.5)     |
   |   state   panel model, rebuilt from reply msgTypes        |
   |   ipc     reader thread (never blocks) | writer           |
   +===========================|===============================+
                               |
        /Q_ServCmdRcver  404x32 |  we WRITE   (not sole writer)
        /Q_ServCmdTrsmtr 556x32 |  we RECEIVE (must be SOLE reader)
                               |
   +===========================|===============================+
   |  /tuxedo   Qt, glibc 2.5, UNCHANGED                       |
   |   CReceiverThread::run  ->  84 command codes              |
   |   CAL / ECP  <------------------------------> VISTA-21iP  |
   |   /mqUI_Input_Queue -> CUiReceiverThread (intra-tuxedo)   |
   +===========================================================+

   Also on the bus, unchanged. We do not receive on any of these:
     supervis      /g_mqSupervisionThreadIn, holds and kicks /dev/watchdog
     TotalConnect  writes /Q_ServCmdRcver (284-byte messages)
     vidApp        /mq_TuxAppVidRecEvent, /mq_VidRecWebAppEvent
     VoiceRecog    /Q_VoiceTux
   tuxedo also holds three of those four (MEASURED). Directions not
   established for all. Hence: open two, receive on one.
```

### 2.5 What we owe `ha-tuxedo-touch`

The Home Assistant integration is the reason anyone runs this firmware. A
rewrite that silently breaks somebody's automations on flash day gets rolled
back, after which nothing is fixed. So the compatibility surface is explicit and
small:

- **A legacy push endpoint** emitting the same frames, byte for byte:
  `multipart/x-mixed-replace`, boundary `EH912ZZ`, latin-1, `:`-separated
  fields, the `0xFE`/`0xFF` state byte, the 3-4x `-1` filler frames. We can
  produce these because we hold the same 556-byte replies Barracuda held. Where
  a msgType's payload is not yet decoded past `+0x0E`, the shim emits the reply
  verbatim on a diagnostic channel rather than guessing.
- **Arm / disarm / status** by command code, same semantics.

Everything else is a new API and the integration migrates at its own pace.

Two corrections that matter to anyone reimplementing frames:

- Field 3 of an id-21 frame is emitter-dependent. From
  `sltSendChangedPartitionStatus` it is `GetOnlineStatus()` (and the msgType is
  rewritten 21→22 when that is not 1); from
  `sltSendPartitionDetailsToWebClient` it is the constant 7. **READ.** It is not
  the partition number, and it is not one thing.
- The `0xFE`/`0xFF` byte is `enableDisarmOption()`: `0xFF` when the Disarm option
  is enabled (armed/arming), `0xFE` when it is not. **READ**, and it matches the
  measured semantics exactly.

And the security decision: the push stream currently needs **no credential** on
port 80 or 6280 and leaks live arm/disarm state to anything on the LAN.
**MEASURED.** That does not survive into a rewrite whose purpose is to secure the
panel. The fix ships with its own escape hatch in the same release:

- Stream served on 443 under TLS, gated by a per-client bearer token (header
  form, plus a query-parameter form for clients that cannot set headers on a
  long-lived stream), tokens issued by an admin command, stored hashed,
  individually revocable.
- On port 80 the stream is **off by default**. `push.legacy_plaintext = true`
  re-enables it; while enabled the server logs a warning hourly and flags it on
  the status endpoint. The flag is removed one release later.

Note for stage planning: connecting a push client is not read-only. The measured
`G.` connection returned `0:504:...`, which is `registerclient`'s reply — so
registering triggers command 500, which flushes all 32 queued replies. Every
extra push client transiently drops pending events for the others. This already
happens today with `tuxedo_push.py`; it is accepted behaviour, not a new risk,
but it must not be described as a passive tap.

### 2.6 HTTP behaviour

Port 80 answers exactly two things: a `301` to `https://` **preserving path and
query**, and (only while the legacy flag is on) the push stream. No login form,
no `200` on an HTML page, no `Set-Cookie`, no credential accepted, ever.

**Correction to the motivating claim.** The mapping said the vendor "hands the
user back to plaintext" because `/redirect.html` returns a `http://` `Location`.
The review measured both schemes: `Location` mirrors the request scheme. Over
TLS, `/redirect.html` returns `200` and `/tuxedoapi.html` redirects to `https://`.
A browser that follows `/` → `https://.../redirect.html` stays on TLS. The real
defects survive and are enough on their own: the plaintext listener serves the
login page `200` in the clear (6,311 bytes, **MEASURED**), and `/` redirects to a
fixed path rather than the requested one.

**No HSTS initially.** Browsers ignore it on an IP-literal host, so it buys
nothing for the `https://203.0.113.5/` access pattern everyone actually uses; and
on a hostname it removes the click-through interstitial, which is precisely the
lockout the cert design exists to prevent. Revisit only after ACME is in use and
renewal has survived two cycles, then with a short `max-age` and no preload.

**The panel cannot firewall itself** — no `iptables`, no netfilter, zero loadable
modules (`LIVE-RESULTS.md`). Network-level restriction stays an off-device
concern.

---

## 3. The cert path

### 3.1 The constraint that decides the default

**Entropy, corrected.** The mapping reported "~21 bits/minute, replicated
twice", and derived a first-boot rule from it. The review refuted the rate: the
two 54 s runs sampled the rising side of an oscillation, and the pool *dropped*
173 → 130 between them. An independent 100 s run at 10 s intervals gave
`173 173 173 184 184 184 131 131 131 142 142` — net **-31 bits**, a bounded band,
never approaching `poolsize` 4096. **MEASURED.**

The corrected reading: `entropy_avail` sits at an equilibrium of roughly
**130-185 bits**, where consumption matches production. It does not accumulate.
Waiting does not help, and the "wait 10 minutes for ~210 bits" rule has no
support and is dropped.

Supporting facts, all **MEASURED**: no `/dev/hwrng`; `lsmod` empty (monolithic
kernel); `dmesg` shows only `alg: No test for stdrng (krng)`; no random-seed
save or restore anywhere in `/etc/rc.d/` (every match is a `mknod`/`chmod` of the
device node); reading 64 KB from `/dev/urandom` does not decrement the count.
`getrandom()` is ARM syscall 384 and does not exist on this table (**READ**), so
there is no wait-until-seeded primitive.

**Therefore the default is: the key is generated on the owner's workstation.**
On-device generation is supported as a fallback and gated, never silent. A weak
key is worse than an expired one, because expiry is visible and weakness is not.

### 3.2 Trust models

| | Model | Status |
|---|---|---|
| a | Self-signed leaf | Quickstart. Fine for one or two clients. |
| b | Owner-supplied cert dropped in the config partition | **Not a fourth model — it is the interface.** Every other option terminates in writing `server.key` + `server.crt` to the same directory and reloading. Document it as the always-present escape hatch and the contract the server implements. |
| c | **Small owner-run CA on the workstation** | **Recommended default.** |
| d | ACME / DNS-01 | Supported, run off-panel, with a Certificate Transparency warning. |

Why (c). **INFERRED**, and here is the reasoning that decides it: it is the only
option with a clean rotation story — the leaf changes every renewal and no client
trust store is touched. It works offline with no domain and no DNS provider,
which matters specifically because the thing being secured is an alarm panel that
must keep working when the internet is down. It keeps the long-lived secret on a
workstation rather than on a device in a hallway that anyone can unscrew.

One argument the mapping used for (c) is withdrawn: "Android 7+ ignores
user-store CAs for app traffic" is roughly true but does not discriminate — an
owner-installed private root lands in the same user store and is ignored by the
same apps. It applies identically to (a) and (c). The "Chrome/Firefox handle a
`CA:FALSE` self-signed leaf inconsistently" half is an untested assertion; §5.8.

ACME costs, stated out loud: every issued name enters public CT logs permanently
(`tuxedo.home.example.com` tells a watcher there is a Tuxedo keypad and hands
them a name — use a non-descriptive label or accept it knowingly); 90-day
lifetimes recreate today's failure mode if renewal is unreliable, and this box
has **no cron installed** (**MEASURED** — no `crond`/`cron` binary, no
`/etc/crontab`, no `/var/spool/cron`; busybox provides the applets, so a timer
must be added deliberately); and the ACME account key and DNS API credential
should not live on the panel. Run renewal on the workstation or HA box and push
over SSH. The clock is otherwise adequate for ACME (`rtc0` holds 2026).

### 3.3 Storage

```
/opt/tuxedo/configuration/tls/            0700 root:root
    server.key          0600     EC P-256 private key, PEM
    server.crt          0644     leaf
    chain.pem           0644     leaf + issuing CA (omit the root)
    meta.json           0644     issuer, serial, notAfter, sha256 fpr, source
    rollback/           0700     previous generation, one deep
    seedrng/            0700     busybox seedrng state (on-device path only)
    recovery/           0700
```

`/opt/tuxedo/configuration` is `/dev/mtdblock17`, jffs2, rw, 59 MB with 57 MB
free, and survives a reflash. **MEASURED.**

Two caveats the docs must carry, both of which the mapping got right:

- **The parent directory is `drwxr-xr-x`** and of its 39 entries only
  `UserNamesFile.txt` and `UserNamesFile_sec.txt` are `0600`; `Tuxedo.json`,
  `MailConf.txt`, `NetworkConfig.txt` and the rest are `0644`. **MEASURED.** So
  `tls/` must *assert* its mode and the installer must *verify* it, not inherit.
- **`0700`/`0600` buys less than it looks like on a single-uid box.** Everything
  runs as root; this is not a defence against local code execution. Its real
  value is narrow and worth stating precisely: it keeps the key out of a `tar` of
  the config partition shared for support, and it makes an accidental
  serve-the-config-directory bug non-fatal rather than catastrophic. Overselling
  file modes here would cost credibility.

**JFFS2 has no secure erase.** An unlink writes a deletion node; it does not
overwrite the data node, and the old copy persists until garbage collection
reclaims the block, with no guarantee of when. **INFERRED** from JFFS2 being
log-structured on NAND. `shred` is meaningless on a log-structured filesystem.
Threat-model consequence: **treat every key that has ever been written to the
panel as compromised if the device is physically taken or RMA'd.** Rotation is a
forward-secrecy measure, not erasure.

### 3.4 Generation

**Workstation (default).** `tls/tuxedo-ca.py`:

```
init-ca                     EC P-256 root, 10 years, on the workstation only
issue <name> [--ip A.B.C.D] leaf, EC P-256, <= 398 days, SAN required
renew <name>                new key every renewal, not just a new cert
install-root <client>       scripted trust install for a client
backup                      encrypted root backup, workstation-local
```

Lifetimes: root 10 years, leaf ≤ 398 days, ACME leaf 90 days. The 398-day cap is
client policy rather than cryptography, and rather than track which client
exempts a user-added root across versions, staying under it unconditionally costs
nothing. **Rotate the key on every renewal by default** — a renewal that reuses
the key is how a key quietly lives for a decade.

**Two hard-won details, both measured during this work:**

1. **The panel clock reports local time as UTC — a ~5 hour skew.** `date -u` read
   `00:34:47 UTC` against a host UTC of `05:35:11`, host TZ Central,
   panel TZ unset, `date +%Z` = `UTC`. **MEASURED**, replicated. A certificate
   issued with `notBefore` ≈ now from a correctly-clocked machine is rejected by
   the panel as not-yet-valid — this already happened, `rustls` refused with
   `NotValidYetContext` over a 17,942 s gap. Until the clock is fixed
   (`TUXEDO-NTP-PROPOSAL.md` has the vendor's own switched-off NTP client),
   **`tuxedo-ca.py` backdates `notBefore` by 48 hours** and says so in
   `meta.json`.
2. **The leaf must not be a CA.** `rustls-webpki` rejected a self-signed CA
   presented as the leaf with `CaUsedAsEndEntity`; Go's `crypto/tls` accepted the
   same certificate. **MEASURED.** The trigger is `basicConstraints CA:TRUE` on an
   end-entity cert. A two-level CA + leaf chain fixes it and is what we ship.
   Honest scoping: it was never shown that a *self-signed leaf with `CA:FALSE`*
   would fail, so "a real two-level chain is required" is **INFERRED**, not
   established. It is sufficient; it may not be necessary.

**On-device (fallback only).** `tls/tuxedo-tls selfsign`. Gated, loud, and
correct about what it is:

- Seed from `/opt/tuxedo/configuration/tls/seedrng` with busybox `seedrng`
  (**MEASURED**: `/bin/busybox` is v1.36.1 and has the applet). The applet's
  default dir `/var/lib/seedrng` is useless here because `/var` is tmpfs
  (**MEASURED**: `rwfs on /var type tmpfs, size=20480k`), so the seed must live on
  mtd17 to survive both reboot and reflash.
- Draw from **`/dev/random`** (blocking) into an explicit seed file passed as
  `openssl -rand`, so the wait is visible instead of silent.
- Refuse if `entropy_avail` is below a floor and say why, rather than producing a
  key quietly.
- Device-unique stirring (FEC MAC, mtd content hashes, `/proc/interrupts`
  counters, boot-time jitter) is worth adding, and must be described honestly: it
  **prevents identical keys across units flashed from the same image. It does not
  create entropy** and does not raise the guessing bound against an attacker who
  knows the model and install date. Calling it "adds entropy" would be exactly
  the overclaim this project has been bitten by.
- **`req -addext` does not exist** on the panel's OpenSSL 1.0.1h (**MEASURED**:
  `openssl req -help | grep -c addext` = 0; the flag arrived in 1.1.1), so SANs
  must come from a config file. Ship `tls/openssl-san.cnf.example` with a
  `[v3_req]`/`[alt_names]` block templated with the panel's IP and hostnames. Also
  pass `-config` explicitly on every invocation: `OPENSSLDIR` is `/usr/ssl`,
  nothing is there, and every call warns `can't open config file`. `ecparam
  -genkey -name prime256v1` does work (**MEASURED**).

### 3.5 Expiry must be non-fatal

On a missing, unparseable or expired certificate the server **generates a 7-day
emergency self-signed certificate and serves TLS with it**, rather than refusing
to start.

The reasoning is a deliberate departure from the usual advice. An alarm panel
that will not serve its web UI because a certificate lapsed locks a homeowner out
of their alarm system, which is worse than serving an untrusted certificate to a
LAN client. The current design fails the opposite way — it has served an expired
certificate since 2019 and nobody noticed — so the fix is not "refuse to serve",
it is "always serve, always shout".

The shout is concrete: the emergency certificate's Organization and SAN read
literally `EXPIRED-CERT-EMERGENCY-SELF-SIGNED`, so the browser interstitial and
`openssl s_client` both say so in plain words; plus a syslog line and a flag on
the status endpoint. Config key `tls.on_expiry = self_sign | refuse`, default
`self_sign`.

Monitoring: a daily busybox-`crond` check logging days-to-expiry, warning at 21
days, **and** exposed on an authenticated `/status/tls` JSON endpoint that the HA
integration can scrape into a sensor. A log line alone reproduces the current
failure — nobody reads `SupervisionLog.txt`. The reason we are here at all is
that a certificate expired in 2019 and no mechanism existed to say so.

### 3.6 Recovery

SSH is the recovery channel and must not depend on the web server or its TLS in
any way. **MEASURED** precondition: dropbear on `0.0.0.0:22` with pubkey auth,
both `/usr/sbin/dropbear` and `/usr/sbin/dropbear.musl` present.

```
tuxedo-tls status      subject, SANs, dates, days left, key type, fingerprint,
                       and whether the running server has these files loaded
tuxedo-tls selfsign    the I-lost-everything button; must work offline
tuxedo-tls install     write a pushed key/cert pair, verify perms, rotate
                       the outgoing pair into rollback/
tuxedo-tls rollback    restore rollback/ (one generation, to bound flash cost)
tuxedo-tls reload      re-read key and cert without dropping the listener
tuxedo-tls check       expiry check, for cron
```

`reload` is a hard requirement, not a nicety: rebooting an alarm panel to fix a
certificate is not an acceptable recovery step.

**Trap to document prominently: reflashing is not a TLS recovery path.** `tls/`
lives on mtdblock17, which survives. A reflash costs a 124 MB write and brings
the same broken certificate back. Note the inverse asymmetry too: the SSH host
keys in `/etc/dropbear` are on mtdblock16 and do *not* survive, so a reflash
rotates the wrong key of the two.

Below SSH there is one more rung. `/etc/rc.d/rc.local` already runs
`/mnt/sd/tuxedo-init.sh` at boot if present, and `/dev/mmcblk0p1` is mounted at
`/mnt/sd` with 3.6 GB free. **MEASURED.** Ship
`tls/recovery/tuxedo-init.sh.example` that resets `tls/` to a fresh self-signed
pair. Honesty requirement: this means anyone who can open the keypad and insert
an SD card gets root code execution at boot. That is pre-existing — it is how
this firmware got installed — but a document about securing the panel that omits
it is not credible, so `tls/THREAT-MODEL.md` states it.

Key loss and revocation: back up the **root only**, never the leaf. If the leaf
key is lost and the root is intact, reissue takes seconds and no client is
touched — which is itself the argument for making regeneration a scripted
one-liner. If the root is lost, every client is re-enrolled. For a private CA on
a LAN nothing checks revocation; the real revocation mechanism is short leaf
lifetimes plus, worst case, rotating the root and re-running the client install.
Shipping CRL machinery here would be theatre.

### 3.7 No secrets in the repo, including fixtures

`ci/checks.sh` already has `check_secrets`, and its own comment anticipates this
work. It requires PEM armor **and** a ≥40-char base64 line (so prose mentioning
the header passes), and blocks `*_ed25519 *_rsa id_* *.pem *.key *.crt *.der
*.p12 *.pfx *.jks *.keystore`, excluding `*.pub`. **READ.**

Gaps to close, in priority order:

1. **History.** The check iterates `git ls-files`, i.e. tracked files at HEAD. A
   key committed and later deleted stays in history and stays public. Add
   `git log -p --all -S'PRIVATE KEY'` and a JWK-shaped equivalent as a separate
   `ci/checks.sh --history` mode, run in the Gitea workflow rather than the
   pre-push hook, because it is slow. **This is the single most valuable
   addition.**
2. **ACME account keys are JWK JSON**, matching neither the armor regex nor any
   blocked extension. Add `*.jwk *.p8 *.pk8 *.csr account*.json`.
3. **Generic high-entropy scan**: base64 or hex run ≥ 64 chars in a tracked text
   file, against a documented allowlist. This also catches the AES key/IV pairs
   this project already knows how to extract from `registereddevMAClist.json`.
4. **Nothing under `image/` on a `tls/` path.** Key material must never travel
   inside a firmware image; the image is the artefact people share.
5. **Pre-commit hook running `check_secrets` alone.** Pre-push is too late if a
   colleague has already fetched.

Test fixtures are generated at test time. The tempting shortcut is to commit an
expired certificate with a throwaway key so the expiry-handling test has an
input. Do not: it trips the repo's own check and establishes "this key is fine to
commit" as a precedent someone later applies to a real one. Generating a fixture
in the test is three lines and keeps the invariant absolute, which is the only
kind that survives.

Two smaller checks, each mapping to a failure this project has already had:

- **Leaked LAN addresses.** Commit `0392496` is literally "genericise example
  addresses for publication". Fail on hard-coded RFC1918 addresses or the owner's
  hostnames outside a docs allowlist.
- **Command-existence for panel-side shell.** Same shape as the existing
  `check_dropbear_flags`. **But build it from the PATH links, not from
  `busybox --list`** — the mapping's version would have passed exactly the two
  commands that do not run. Measured corrections: `/usr/bin/nice` is a standalone
  23,495-byte ELF, not busybox-only; `which` *is* in `busybox --list` but has no
  symlink, so `command -v which` fails; `timeout` is likewise listed but not
  linked. The discriminator is whether an applet has a link on `PATH`.

### 3.8 Files this adds to the repo

```
tls/README.md                      four models, the recommendation, the entropy
                                   result, the JFFS2 non-erase caveat
tls/THREAT-MODEL.md                explicit on local-root, physical access,
                                   SD-card boot, and what 0600 does not buy
tls/tuxedo-tls                     POSIX sh, runs ON the panel
tls/tuxedo-ca.py                   runs on the WORKSTATION
tls/tuxedo-tls-push.py             build, scp, chmod, reload, then verify by
                                   connecting back and asserting the served
                                   certificate matches what was pushed
tls/openssl-san.cnf.example        required; no `req -addext` on the panel
tls/acme/README.md                 DNS-01 off-panel, CT warning
tls/acme/renew-hook.sh             push over SSH
tls/recovery/tuxedo-init.sh.example
tls/panel-commands.txt             PATH links on the panel, CI fixture
image/etc/rc.d/init.d/tuxedo-tls-seed
image/etc/cron/certcheck
```

---

## 4. Staged migration

### 4.0 Rules that apply to every stage

1. **The panel must be able to arm and disarm at the end of every stage.** If a
   stage cannot guarantee that, it is split until it can.
2. **A shell stays open.** Never close the last SSH session before the change is
   verified. Have a second one.
3. **One change per stage.** If two things change and the panel misbehaves, the
   bisect costs a day.
4. **Revert is a file move and a process restart, never a reflash.** A reflash is
   the floor, not the plan, and it does not reset `tls/` (§3.6).
5. **Arming, disarming, reboots, reflashes and service restarts are authorised.**
   Lewis, standing: *"you are authorized to make all changes to the live running
   panel"* and *"you can arm and disarm as needed, just leave it in a disarmed
   state when you're done with your test"*. v13 was built, flashed and verified
   under that authorisation on 2026-09-06. What survives from the original rule
   is its reason, not its prohibition: **a false dispatch is a worse outcome than
   any bug this project will find.** So an arming test happens in a defined
   window with the monitoring account on test, the monitoring state is confirmed
   rather than assumed, and the panel is left disarmed.
6. **No failed logins against the vendor server.** P1 removed the permanent
   on-disk lockout on this panel, and the residual 300 s one is per source
   address (`tls/THREAT-MODEL.md` §6), but the tooling still excludes the
   bad-password path by construction because the repo targets stock panels too
   (`TUXEDO-LOCKOUT-PATCH.md`).
7. Anything that must work at boot runs under `qemu-user` in a chroot of the
   extracted rootfs first, `/dev` as shipped (`TRAPS.md` section 6).

### Stage 0 — Baseline and revert kit

**Change:** none on the panel.

**Do:** capture a known-good image and confirm `push-image.sh` + `deploy.py`
round-trip it; record `netstat -lntp`, every `/proc/<pid>/fd` listing, `mount`,
`/proc/mtd`, `df`, `ls -la /dev/mq/`, `/root/Settings/WebConfig.conf`, the
`BARRACUDA` block of `Tuxedo.json`, and `md5sum /opt/webserver/Barracuda`.
Capture 30 minutes of push stream through an arm and a disarm as the conformance
corpus for stage 1. Extend `verify-panel.sh` with the new invariants.

**Proves:** we can put the panel back exactly.
**Revert:** n/a.

### Stage 1 — Off-panel: decoder and conformance corpus

**Change:** none on the panel. Rust workspace `tuxweb/` in the repo.

**Do:** implement the 556-byte reply decoder and the 404-byte command encoder as
a library, plus the legacy frame formatter. Replay the stage-0 corpus through it
and assert byte-identical frame output against what the vendor emitted.

**Proves:** the wire formats are understood well enough to reproduce, before any
of it runs on the panel.
**Revert:** delete a directory.

**STARTED 2026-09-06. The legacy frame layer is done and proven.**
`tuxweb/src/frame.rs` parses and re-emits the multipart stream, against
`tuxweb/tests/fixtures/push-idle-300s.bin` — 300 s captured off the live panel
over the now-authenticated stream, 83 parts. Five tests pass; the load-bearing
one is `reemission_is_byte_identical`, which asserts everything the parser
consumes re-emits byte for byte against real vendor output, raw `0xFE` state
byte included. The module works in `[u8]` throughout precisely because that byte
is not valid utf-8.

Confirmed from the capture rather than inherited: **83 opening boundaries, 83
close delimiters** — the close delimiter does follow every part (§4.10.3b) — and
the payload shapes are `setCid` (once, on connect), `statusMessageText` and
`noOfClient`, with nothing unrecognised.

**Still outstanding for this stage:**

1. ~~*An arm/disarm corpus.*~~ **Captured 2026-09-06**, a real arm-stay → exit
   delay → `Armed Stay` → disarm cycle with the stream held throughout, and the
   panel confirmed back at `Ready To Arm` 3 s after the disarm.
   `tuxweb/tests/fixtures/push-armcycle.bin`, 69 frames: 36 carrying `0xFF`, 16
   carrying `0xFE`. It is the only capture holding the arming states, so
   `arm_cycle_carries_the_0xff_state_byte_and_a_countdown` covers them by
   evidence rather than reasoning, and `reemission_is_byte_identical` now runs
   over both captures.

   The frames the countdown produces:

   ```
   0:21:1:ff:<0xFF>259  Secs Remaining:2      exit delay
   0:21:1:ff:<0xFF>2Armed Stay:2              armed
   0:21:1:fe:<0xFE>1Ready To Arm:2            disarmed
   ```

   Worth noting against §2.5: the REST `GetSecurityStatus` view of the same
   cycle was visibly stale — it reported `34  Secs Remaining` for six
   consecutive polls across 30 s while the stream counted down correctly. The
   stream is the accurate source, which is the whole reason the integration uses
   it.

   Arming and disarming are scripted so this is not re-derived a third time:
   `D:/temp/tux-arm.py` and `D:/temp/tux-disarm.py`. They live outside the repo
   because they need the panel code, and `tux-disarm.py` exits non-zero unless
   it confirms the panel actually reached a disarmed state.
2. ~~*The 404-byte command encoder.*~~ **Done 2026-09-06**, with the reply
   decoder, in `tuxweb/src/ipc.rs`. Structure recovered below; the library is
   22 passing tests, the strongest being
   `every_captured_frame_is_reproducible_from_its_fields`: it walks both live
   captures, recovers the fields behind each frame, re-formats them, and
   requires the result to equal the original byte for byte.
   **150 frames reproduced, 0 unaccounted for** — every `statusMessageText` in
   both captures. The guard is `skipped == 0`, so the test now fails if the
   panel ever emits a shape the module cannot produce.

   Two things surfaced in closing that gap. The panel **repeats the
   registration frame with `-1` in the type slot** (`0:-1:1:P1  H:1:0:3:3`),
   exactly as it repeats a status frame — a parser reading that field as
   unsigned drops it silently. And two frames are not formatted from a reply at
   all: a bare `-1` (36 times across the captures) and `Client Connected`, kept
   as `literal::BARE_FILLER` and `literal::CLIENT_CONNECTED` because a
   replacement must emit them verbatim or a consumer notices their absence.

#### The 404-byte command, from the binary

Anchored on `setarmwithcode` and `setdisarmwithcode`, which are the
`AdvancedSecurity/ArmWithCode` and `DisarmWithCode` endpoints driven by
`D:/temp/tux-arm.py` today, so their real-world effect is known rather than
assumed.

The outbound command is **built in a global buffer at `0x55d8d0`**, not on the
stack — the opposite of `/tuxedo`'s stack-built replies, and worth knowing
because a global build buffer is not reentrant:

```
0x1afe4  ldr lr, [pc,…]   -> 0x55d8d0     the command buffer (GLOBAL)
0x1afec  str ip, [lr]                     cmd+0x00
0x1aff8  str ip, [lr, #4]                 cmd+0x04  <- caller param [fp,#8]
0x1b004  str ip, [lr, #8]                 cmd+0x08  <- caller param [fp,#0x6c]
0x1b010  str ip, [lr, #0xc]               cmd+0x0C  <- caller param [fp,#0x70]
0x1b00c  mov r2, #0x194                   404
0x1b014  ldr r0, [r3]                     mqd from the global at 0x55ae68
0x1b018  mov r3, #1                       priority 1
0x1b01c  bl  mq_send
```

`mq_send(mqd, 0x55d8d0, 404, prio=1)` — identical in `setdisarmwithcode`,
`setPartitionArmed` and every other `set*` handler checked.

**`+0x04` is the command code. `+0x0C` appears to be the USER CODE.** An earlier
version of this section said `+0x0C` carried the command, on the strength of two
constants. Sweeping `+0x0C` across all 31 senders and then reading the result
refuted it:

- `setClientRegister` writes **500 at `+0x04`**, not `+0x0C`, via
  `stm r4, {r5, ip}` — which stores `+0x00` and `+0x04`. Its `+0x0C` is zero.
  500 is the command §B7 independently records as setting `clients_connected`
  and calling `registerclient`, so `+0x04` is the command field.
- `setOccupancyMode` writes `0x457` = **1111** at `+0x0C`, with `+0x04` taken
  from a caller parameter.
- `setPartitionArmed` writes `0x4d2` = **1234** at `+0x0C`, same shape.

I briefly read 1111 and 1234 as **user codes** — they are the two commonest
default alarm codes, and the handlers taking a real `uCode` from the request
read `+0x0C` from a caller parameter — and flagged it as a possible security
finding. **Reading the consumer refutes that**, which is why it was labelled
unverified rather than asserted.

**The consumer, confirmed.** `CReceiverThread::run` @`0x147158` receives into
`sp+0x2f4` with `osal_MqRecv(q, buf, 404)` and immediately does:

```
0x1471dc  ldr ip, [sp, #0x2f8]     buf+0x04
0x1471e8  cmp ip, #0x70            ...and dispatches on it
```

So **`+0x04` is the command code on both sides** — Barracuda writes it,
`/tuxedo` dispatches on it. That much is now confirmed end to end.

**`+0x0C` is not a user code.** It is read exactly once in the whole loop, at
`0x147b58`, and paired with `+0x08`:

```
0x147b58  ldr r3, [sp, #0x300]     buf+0x0C
0x147b5c  ldr r2, [sp, #0x2fc]     buf+0x08
0x147b74  bl  CReceiverThread::sigsimulateTouchPoints
```

They are **touch coordinates** for that one command. So `+0x08`/`+0x0C` are
command-specific parameters, not fixed-meaning fields, and the 1111/1234
constants in `setOccupancyMode`/`setPartitionArmed` remain unexplained — but
nothing supports calling them user codes.

**Worth its own note: the panel accepts simulated touch input over this queue.**
`sigsimulateTouchPoints` takes an x/y pair straight from a Barracuda-sent
message. That is a capability the console-mode work (§4.10.7) should know about,
and a thing any replacement inherits the ability to do.

#### The command dictionary, recovered from the consumer's dispatch

`CReceiverThread::run` dispatches 40 codes, and because `/tuxedo` keeps its Qt
slot names the meaning of each comes free:

| code | slot | code | slot |
|---|---|---|---|
| 1 | `sltRequestArmAway` | 55 | `sltUploadCameraDB` |
| 2 | `sltRequestArmStay` | 56 | `sltGetCameraCredentials` |
| 3 | `sltRequestDisarm` | 58 | `sltDeleteAllCameras` |
| 5 | `sltRequestPartitionStatus` | 104 | `sltRequestZwaveDeviceAdd` |
| 7 | `sltRequestMultiPartitionArmStay` | 106 | `sltRequestZwaveDeviceFrmv` |
| 8 | `sltRequestMultiPartitionArmNight` | 107 | `sltRequestZwaveDeviceAbort` |
| 12 | `sltRequestAllZoneCurrStatus` | 109 | `sltRequestZwaveLightStatSet` |
| 13 | `sltRequestBypassAllZones` | 110 | `sltRequestZwaveDimmerStatGet` |
| 15 | `sltRequestToBypassZones` | 114 | `sltRequestZwaveThermoStatAllInfoGet` |
| 17 | `sltRequestEventLogUpload` | 115 | `sltRequestZwaveThermoStatAllInfoSet` |
| 18 | `sltRequestGetHomePartDetails` | 117 | `sltRequestZwaveThermostatModeSet` |
| 25 | `sltRequestMultiPartitionArmAwaySelected` | 119 | `sltRequestZwaveTermTarTempGet` |
| 27 | `sltRequestMultiPartitionArmNightSelected` | 120 | `sltRequestZwaveTermTarTempSet` |
| 29 | `sltRequestMultiPartitionDisarmSelected` | 122 | `sltRequestZwaveTermFanModeSet` |
| 53 | `sltUpdateCamera` | 125 | `sltRequestAllHADeviceStatus` |
| 508 | `Increase_RemoteWeb_usage_num` | 127 | `sltRequestZwaveTermSaveEnergyModeGet` |
| 604 | `SetSessionState` | 129 | `sltRequestZwaveAllLightsOFF` |
| 700 | `EmitSignalOfAPIRequest` | 147 | `sltRequestZwaveGarageDoorStatSet` |
| 800 | `apl_hAsceneInitialize` | 888 | `sltSceneExecuteOnId` |

Code 102 lands back on `osal_MqRecv` — the ignore-and-loop path.

**This is the arm/disarm ABI in plain sight:** 1 away, 2 stay, 3 disarm, with
7/8/25/27/29 the multi-partition forms. §2.5 commits a replacement to "arm /
disarm / status by command code, same semantics" — these are those codes, and
they are now written down rather than inferred from behaviour.

**Registration: 500 out, 504 back, and the loop closes.** `setClientRegister`
writes **500** into `+0x04`, and it *is* dispatched — the table above simply
missed it:

```
0x1472e8  cmp ip, #0x1f4            500
0x1472ec  bne #0x14723c             skip if not
0x1472f8  bl  Increase_LocalWeb_usage_num
0x147300  bl  CReceiverThread::registerclient
```

**The 40-code table was a lower bound; re-running with both forms gives 56.**
It had followed only `cmp/beq` and missed every case written `cmp/bne skip` —
the same undercount made earlier against Barracuda's dispatch and already
written into TRAPS. Codes the corrected pass adds: **4** `ArmNight`, **9**
`MultiPartitionDisarm`, **14** `BypassClearAllZones`, **19**
`requestconsolemode`, **52** `AddCamera`, **57** `StartCameraDiscovery`, **105**
`ZwaveDeviceDel`, **108** `ZwaveLightStatGet`, **111** `ZwaveDimmerStatSet`,
**121** `ZwaveTermFanModeGet`, **154** `readCRCJSONFile`, **500** register,
**608** `ZWsendMsgToZSDOutThread`.

**The table now lives in `commands.tsv`**, not only in this prose — 79 rows of
`code / handler_va / handler / barracuda_sender` covering 84 codes, alongside
`patches.tsv` as a machine-readable source of truth, regenerated from the binary
by `dispatch_tree.py`.

**`300` is a case after all.** It was published from a `cmp ip,#0x12c / bhs`,
then withdrawn as a binary-search pivot. Both readings were wrong: that `bhs`
is the lower bound of a range, and 300-303 all reach
`CReceiverThread::sltSceneExecute`. A comparison is not a case and not a pivot
on its own — it is one constraint, and only the whole path says which codes
reach a block. That is why the table is now derived from the constraints
instead of from instruction shapes; see `TRAPS.md` §2.

#### The sender side, and why four of them have no constant to find

`sender_args.py` resolves eleven codes to compile-time constants in Barracuda —
55, 57, 58, 109, 111, 117, 120, 125, 126, 700, 888. Four senders resisted, and
the reason turned out to be structural rather than a gap in the tool.

`setarmwithcode`, `setdisarmwithcode`, `setOccupancyMode` and `setPartitionArmed`
each take the code in `r1`. Their only caller is `set` @`0x15a00`, which has
**zero static callers and no data word holding its address** — because it is
registered, not called: `WnmpModule_constructor` @`0x15740` is handed `set`
together with its sibling `get` @`0x15778`. Both dispatch on a WNMP OID leaf,

```
ldrh r1, [r0] ; bic r1, r1, #0xf000 ; sub r1, r1, #8 ; cmp r1, #0x43
ldrls pc, [pc, r1, lsl #2]        ; a 68-entry jump table
```

and each of the four arms does `ldm r4, {r0, r1, r2, r3}` with `r4` being
`set`'s own third argument. **The command code is word 1 of the request value
block, not a literal.** No bounds check appears between the `ldm` and the `bl`,
nor in the sender before the `str` into `buf+0x04`.

So on this path the code is request data, and the thing bounding it is the
receiver: the 84 cases, with everything else reaching the default arm. Stated
narrowly on purpose — that covers these two hops. Whether the value is
attacker-controlled end to end depends on validation earlier in the REST tier,
which has not been read, and that tier does require TLS and a session (§4.1).

**Reachability of codes 1, 2 and 3 is not in doubt regardless**: they are driven
live by `D:/temp/tux-arm.py` and `tux-disarm.py` against the panel, which is how
the arming path is exercised in every session.

#### Console mode, end to end

With command 19 confirmed the whole chain is now known, and it is the concrete
form of §4.10.7:

| step | mechanism | state |
|---|---|---|
| 1. a client asks for console mode | command **19** on `/Q_ServCmdRcver` → `CReceiverThread::requestconsolemode` @`0x13db5c` | works |
| 2. the panel sends display updates | msgType **20** from `wsltHandleRawDataFromPanel` | works, and P10 makes the text real rather than a 14-byte placeholder |
| 3. Barracuda relays them | **no case for 20** in `gettuxedoIPCCommFunc` | **dropped here** |

Every link exists except the third, and the third is one dispatch case in the
replacement. Command 19 verified individually: `cmp ip,#0x13`, `bne`, and
`requestconsolemode` lists `CReceiverThread::run` among its callers.

Reading `registerclient` explains the exchange:

```
0x13c308  bl osal_MqFlush           its FIRST act -- drains the reply queue
0x13c310  mov r2, #0x1f8            504
0x13c318  str r2, [sp, #4]          reply+0x04  <- msgType 504
0x13c31c  bl getZWControllerStatus
0x13c324  bl GetPanelCalImplementation
0x13c32c  bl GetOperationMode
0x13c344  bl GetTotalPartitions
0x13c354  bl GetCurrentPartition
```

So registration produces the **msgType 504** reply, which is exactly the
`0:504:1:P1  H:1:0:3:3` frame captured on connect — the panel details it gathers
here are those fields. Two things previously recorded separately are the same
event.

It also confirms §B7 from the other side: `registerclient`'s first action really
is `osal_MqFlush` on the reply queue, so **registering a client discards every
pending reply**. Any replacement that registers must expect to lose whatever was
queued, and §2.5's warning about a second EH client costing a queue flush is
this behaviour.

`registerclient` is called from `CReceiverThread::run` (the site above) and from
`CReceiverThread::sendModeChange`; `unregisterclient` @`0x13c00c` likewise from
`run`.

**A retracted claim, and the reason matters more than the claim.** One commit
earlier this section asserted "`/tuxedo` contains no `cmp <reg>, #500` at all",
from a scan over the whole `.text`. That scan is worthless: **capstone's
`disasm()` stops at the first word it cannot decode**, and a linear pass over
this binary's `.text` decoded **442 instructions — 0.03% of the section** —
before halting in the first literal pool. It reported absence because it never
looked. Any "X does not appear in this binary" produced that way says nothing.

Ruled out on the way: **`th_processAplEcpOutput` is not the consumer.** It takes
100-byte messages and dispatches on ASCII — `0x30`–`0x39`, `*`, `#`, `A`–`D`,
`a`–`d` — so it is the ECP **keypad character** handler. Noted because `A`–`D`
are the panic keys `TUXEDO-AUDIT-BUGS.md` flags as needing no user code.

**Verified end to end:** the buffer address, size, priority, queue handle
global, the field offsets, the constants quoted above, and that `+0x04` is the
command code — written by Barracuda, dispatched on by `/tuxedo`. **Refuted:**
the user-code reading of `+0x0C`. **Still unexplained:** why
`setOccupancyMode` and `setPartitionArmed` bake 1111 and 1234 into `+0x0C`.

**The sweep across all 31 senders is a candidate table, not a census** — it
missed `setClientRegister` entirely, a case already known to be real, because
that handler writes the field with `stm` rather than `str`. Codes recovered from
it must be confirmed by reading the handler.

#### The reply decoder: dispatch map recovered from the binary, 2026-09-06

The decoder cannot be built against a captured corpus the way the frame layer
was — reading the reply queue **takes** the message (§1.7 B5), so capturing
replies would starve Barracuda. It has to come out of the binary. It now
partly has.

**The struct is confirmed at the receive site**, not inferred.
`gettuxedoIPCCommFunc` @`0xd5d0` calls `osal_MqRecv(q, buf, 0x22c)` — 556 —
into `sp+0x274`, then:

```
0xd614  ldr  r8, [sp, #0x278]     msgType   = buf+0x04   <- the dispatch value
0xda80  ldr  r7, [sp, #0x274]     sessionId = buf+0x00
0xda94  add  sl, r6, #0xe         text      = buf+0x0E
0xdac0  ldr  r5, [sp, #0x27c]     arg       = buf+0x08
0xdac4  ldrb r6, [sp, #0x282]     buf+0x0E again, as a BYTE
```

That last one settles something the frame docs left ambiguous: the `0xFE`/`0xFF`
state byte is **the first byte of the text field**, read as a byte, not a
separate struct member. It is why frames must be handled as latin-1 bytes.

**Dispatch is a binary search tree on `r8`** (`cmp`/`beq`/`bhi`), not a compare
chain and not a jump table. Cases come in two shapes, and reading only the first
undercounts by a third: `cmp r8,#N; beq handler`, and the inverted
`cmp r8,#N; bne skip; b handler`. Taking both gives **40 cases**.

**The whole frame-emitting surface is three functions.** `bprintf` @`0x1e0f4`
(always paired with `bflush` @`0x1df84`) has exactly three callers in the
binary — a question that cannot overrun a window, unlike scanning outward from a
handler:

| emitter | what it produces |
|---|---|
| `gettuxedoIPCCommFunc` | the panel status frames, per msgType |
| `checkvalidSessions` (from `sessionValidCheckCloseTimerHandler`) | `%d%s` with `':Logout'` — session teardown |
| `videoRecIPCCommThreadFunc` | camera/recording frames, 7 call sites |

Inside the dispatcher, **at least 16 of the 40 handlers emit frames** before
their first branch:

| msgType | handler | formats |
|---|---|---|
| 19 | `0xf20c` | `%d%s%d%s%s` |
| 21 | `0xda80` | `%d%s%d%s%d%s%x%s%s%s%d`, then 3x `%d%s%d%s%s` |
| 22 | `0xd9b8` | `%d%s%d%s%s%s%d`, then 2x `%d%s%d%s%s` |
| 25, 51 | `0xf234` | `%d`, `%d%s%d%s%d` |
| 29 | `0x102a0` | `%d%s%d%s%d%s%d%s%d%s%s` |
| 55 | `0xf2a0` | four distinct, up to `%d%s%s%s%s%s%s%s%s%s%s%s%d` |
| 56 | `0xf5b4` | `%d%s%d%s%s%s%s%s%s` |
| 59 | `0x10574` | `0:%d:%d` — separators baked in, unlike the rest |
| 104, 105 | `0x10428` | `%d`, `%d:%d:%d` |
| 112 | `0x102f0` | `%d`, `%d%s%d%s%d%s%d` |
| 130 | `0x10384` | `%d%s%d%s%d%s%d` |
| 132, 133 | `0x10484` | `%d`, `%d:%d:%d` |
| 504 | `0xf638` | `%d%s%d%s%d%s%s%s%d%s%d%s%d%s%d` |

msgType 504's format has 15 conversions, which is exactly the shape of the
captured `0:504:1:P1  H:1:0:3:3` — 8 fields with 7 `':'` separators between
them. That agreement is the check on this table.

**16 is a lower bound, and msgType 18 shows why.** Handlers may set up the
argument frame and then **branch to a shared two-instruction tail** that does
nothing but `bl bprintf; b 0x104a8` — `0x103bc` is one such tail. A walk bounded
at the first unconditional branch cannot see those.

msgType 18 decoded, and it matches the capture exactly:

```
0xf1bc  r5 = a global buffer;  r4 = sp+0x282 = reply+0x0E (text)
0xf1d0  strcpy(global, text)        <- the text is COPIED to a global first
0xf1d8  HomePartChanged(text)
0xf1dc  setQuickArmStatus()
0xf1e4  getQuickArmStatus()  -> [sp+0x10]
0xf1ec  fmt = '%d%s%d%s%s%s%d'
0xf208  b 0x103bc                   <- the shared bprintf tail
```

`sessionId : msgType : <global text> : getQuickArmStatus()` = the captured
`0:18:1 P1  H:2`.

Two things a reimplementation needs from this. **msgType 18 shares msgType 22's
format**, so format string alone does not identify a message. And **the text it
prints is a global copy, not the reply buffer** — 18 `strcpy`s the reply text
into a global before formatting, so the value emitted is whatever that global
last held. Reading the reply alone is not enough to reproduce the frame.

**Two earlier versions of this table were wrong, in opposite directions.** One
listed nine formatters of which seven were false, from a scan that ran a fixed
distance past each handler entry and picked up the *next* handler's format
string — they sit 0x20–0x40 bytes apart, so an unbounded window is guaranteed to
cross. The correction then said "only 21 and 22 emit", which was measured over
just those nine handlers and stated as if it covered all forty; msgType 19 calls
`bprintf` eight instructions into its handler.

Separately and still true: 1, 2, 103, 109, 111, 147 and 154 emit nothing
directly. They `malloc(0xc)`, read a byte at **`reply+0x92`** plus a halfword
from a global table, and `pthread_create` one of two named workers —
`pushSecurityStatus` @`0xd180` (spawned by 21 and 22) or
`pushNewZwaveStatusToOthers` @`0xd23c`. Neither worker calls `bprintf`, so they
fan state out by another route.

The remaining msgTypes — 3, 4, 5, 6, 7, 8, 9, 19, 25, 26, 27, 29, 51, 55, 56,
59, 61, 62, 104, 105, 112, 125, 130, 132, 133, 160, 161, 162, 716 — have not
been characterised.

#### The frame grammar, and two msgTypes decoded end to end

The formatter is `bprintf` @`0x1e0f4` followed by `bflush` @`0x1df84`, called as
`bprintf(session, fmt, r2, r3, [sp+0], [sp+4], …)`. The repeated `%s` is a
constant `':'` at `0x84f5c` — **the separator is an argument, not part of the
format string.**

**msgType 21, the status frame, decoded and checked against the capture:**

```
%d %s %d %s %d %s %x %s %s %s %d
|  |  |  |  |  |  |  |  |  |  +-- getQuickArmStatus()
|  |  |  |  |  |  |  |  |  +----- ':'
|  |  |  |  |  |  |  |  +-------- reply+0x0E  text
|  |  |  |  |  |  |  +----------- ':'
|  |  |  |  |  |  +-------------- reply+0x0E  FIRST BYTE, as hex -> the fe/ff
|  |  |  |  |  +----------------- ':'
|  |  |  |  +-------------------- reply+0x08  arg
|  |  |  +----------------------- ':'
|  |  +-------------------------- msgType
|  +----------------------------- ':'
+-------------------------------- reply+0x00  sessionId
```

That produces exactly the captured `0:21:1:fe:þ1Ready To Arm:2`, and names a
field the frame docs did not: the trailing `2` is **quick-arm status**.

**The `-1` filler frames are explained.** The same handler then calls `bprintf`
three more times with `%d%s%d%s%s` and `mvn r5,#0` (`-1`) where the msgType
would go: `sessionId : -1 : text`. That is the `0:-1:þ1Ready To Arm` seen 3–4
times per status in the capture. §2.5's "3-4x `-1` filler frames" is therefore
not a transport quirk to imitate blindly — it is a deliberate repeat emitted by
the status handler itself.

**msgType 22:** `%d%s%d%s%s%s%d` = `sessionId : msgType : text : arg`, then two
fillers.

Those two are the whole synchronous frame path. Everything else observed on the
wire — `0:18:`, `0:504:` — comes from a worker thread, which is the next thing
to follow: `pthread_create` is called with a 12-byte argument holding
`reply+0x92`, a halfword from a global table, and a discriminator byte at
offset 8 (`mvn ip,#0x6c` = -109 for msgType 147, `r8` itself for 109/111).

Four handlers serve two msgTypes each: `0xf234` (25, 51), `0x10274` (26, 27),
`0x10428` (104, 105), `0x10484` (132, 133).

**40, not the 43 stated in §1.3.** The three-case gap is unexplained and is
probably a default or fallthrough path; `r8` is also copied to `r0` at three
sites, which have not been followed. Recorded as a discrepancy rather than
rounded away.

**This is a map of what Barracuda HANDLES, not of what `/tuxedo` SENDS, and the
difference is the whole reason for §4.10.7.** The clearest case is **msgType 20,
which is absent from the list above and is very much real**: `/tuxedo`'s
`wsltHandleRawDataFromPanel` copies the keypad display and `osal_MqSend`s type
20 on `/Q_ServCmdTrsmtr`. Barracuda has no case for it, so it is dropped at the
edge — that is the console-mode defect, and it is why P10, which makes `/tuxedo`
put the *real* display text in that message instead of a 14-byte placeholder,
still does not produce a working console today.

A replacement receives type 20 like any other reply. Console mode costs it one
more case in the dispatch, which is what "console mode arrives free" in §4.10.7
means. Do not read a gap in this table as "the panel never sends that".

#### The sender side, measured: TWO message types are dropped, not one

Anchored on the one known case rather than scanned for loosely. `/tuxedo` builds
the reply on the stack and sets the type at `+0x04` immediately before a
556-byte send — `wsltHandleRawDataFromPanel` does exactly this for type 20:

```
0x13da24  mov r3, #0x14        20
0x13da2c  str r3, [sp, #4]     the msgType slot
0x13daf0  mov r2, #0x22c       556
0x13daf4  bl  osal_MqSend
```

Applying that exact shape to every caller of `osal_MqSend` gives the types
`/tuxedo` sends: **1, 4, 20, 21, 51, 59, 60, 61, 62, 504**. Eight are handled.
**Two are sent and silently dropped:**

| msgType | sender | what is lost |
|---|---|---|
| 20 | `CReceiverThread::wsltHandleRawDataFromPanel` | the keypad display — console mode |
| 60 | `CAccountsSetup::sendUpdateCommandToWeb`, `CInitialAccountsSetup::sendUpdateCommandToWeb` | account updates never reach the web tier |
| 999 | `CVoiceTuxThread::processGlobalSet` | voice-command results |

Each was verified on its own rather than trusted from the sweep. 60 is
`mov r3,#0x3c; str r3,[sp,#4]; bl osal_MqSend` with `r2 = 0x22c`; 999 is the
same shape with the constant coming from a literal pool rather than an
immediate, which is why a `mov`-only scan missed it first time round.

**Two candidates were rejected as scan artifacts.** `msgType 0` from
`CHomeScreen::sltHandleDoorBtnPress` and `msgType 20696` (`0x50D8`) from
`CReceiverThread::sltSendUserCodeAcceptedMsg` both come from a register the
tracker had stale: in the latter the pool value is a **GOT offset** used by
`ldr lr,[r0,r3]`, and `r3` is reassigned before the store. Neither is a message
type.

**The HTTP-status reading of 504 does not hold.** It is a natural guess — 504 is
the only value in that range — but `401`, `403`, `404`, `500`, `502` and `503`
appear in **neither binary**, as a sent type or a dispatch case. 504 is the
registration-data frame emitted on connect, which the wire contract already
names, and the captured `0:504:1:P1  H:1:0:3:3` is that frame.

**How big is the gap? Measured, because "lower bound" was doing too much work.**
Across the callers of `osal_MqSend` that perform a 556-byte send:

| | count |
|---|---|
| stores to `+0x04` resolved to a constant | 21 |
| stores to `+0x04` **not** resolved | 8 |
| callers with **no store to `[sp,#4]` at all** | 55 |

That last row is the honest headline: the scan assumes the message is built at
the stack base, and **most senders do not match that shape**. They build it
against another base register, or memset and fill fields elsewhere. So this
characterises a minority of the sender side, not almost all of it.

**And the unresolved sites are the interesting ones**, which is exactly the luck
one should expect:

```
0x0013c454  CReceiverThread::sltSendUserCodeAcceptedMsg
0x0013dc08  CReceiverThread::sltSendUserCodeDeclinedMsg
0x0014134c  CReceiverThread::sltSendUserRequiredMsg
0x0013c4e8  CReceiverThread::sltQuickArmStateChangeMsg
0x00142a10  CReceiverThread::sltGetCameraCredentials
0x0014322c  CReceiverThread::sltUploadCameraDB
0x00045aa8  StartVoiceRecogApp
0x00444578  writeCRCJSONFile
```

`sltSendUserCodeAcceptedMsg` and `sltSendUserCodeDeclinedMsg` are the
`VALID USER CODE` / `USER CODE DECLINED` path this document already argues a
client should wait on instead of guessing whether a command took effect.

**Why they are unresolvable by any constant scan, established rather than
assumed.** These functions build the message at **`sp+4`**, not `sp` —
`add r5, sp, #4` then `add r4, r5, #0xe` for the text field — so the type lands
at `[sp,#8]`, and `[sp,#4]` that the earlier scan read is the *sessionId*. Worse
for static analysis, the type is not a literal at all:

```
0x13c414  ldr lr, [r0, r3]      r3 is a GOT offset; lr <- an OBJECT FIELD
...
0x13c460  str lr, [sp, #8]      that field IS the msgType
```

`sltSendUserCodeDeclinedMsg` does the same with `ip`. So the msgType for these
messages is **read from a field of the `CReceiverThread` object**, not baked
into the instruction stream. No amount of constant tracking will recover it; it
needs the field's initialiser or a runtime observation.

**And runtime observation is half-blocked.** The accepted path fires on every
successful disarm, but §"Captured live" above already records that **no
`VALID USER CODE` frame appeared** during a full arm/disarm cycle — consistent
with these being among the dropped types. The declined path would need a
deliberately wrong code, which the tooling excludes by construction, so it
cannot be observed at all.

This also explains the 55 senders with no `[sp,#4]` store: **the struct base is
per-function.**

**Do not trust either sweep as a census — this was tested, not assumed.** An
earlier version of this section proposed locating the base from the
`add rB, sp, #N` / `add rT, rB, #0xe` idiom and reading `[sp, #N+4]`. That was
written as a recipe and then run, and it is **worse than the scan it was meant
to fix**: 0 types resolved, 194 functions where the idiom never appears. The
reason is immediate in hindsight — `wsltHandleRawDataFromPanel`, the one sender
known to be correct, builds the message at **`sp` itself** with no
`add rB, sp, #N` anywhere, so requiring the idiom excludes the case that
works.

The honest position on method: **no sweep here is reliable.** The `[sp,#4]`
scan matches senders whose base is `sp`; the idiom scan matches senders whose
base is `sp+N`; neither covers both, and some senders take the type from an
object field where no static scan can reach. The three dropped types above are
trustworthy **because each was verified individually by reading its sender**,
not because any sweep vouched for them. Treat the sweeps as a way to generate
candidates and nothing more.

So the replacement gains **three** capabilities the vendor stack cannot deliver
at all, and none requires a panel-side change — all three messages already
arrive on `/Q_ServCmdTrsmtr` every time the panel produces them.

**Why this is trustworthy:** the method was validated against a result derived
independently and earlier — msgType 21 at `0xda80` with
`%d%s%d%s%d%s%x%s%s%s%d`, which `TUXEDO-AUDIT-BUGS.md:94` already recorded.
Two earlier attempts were **wrong and discarded**: attributing each format to the
nearest preceding `cmp` blamed everything on msgType 0, because `cmp #0` is a
null check rather than dispatch; and following only `beq` edges reported 26
cases and missed msgTypes 1, 111 and 147, all three of which do format frames.

### Stage 2 — On-panel read-only probes, `/tmp` only

**Change:** static musl binaries in `/tmp`, run and removed. Nothing else.

**Do:**

- `mq_open(name, O_RDONLY|O_NONBLOCK)` + `mq_getattr` + `close` on both queues.
  This **converts the queue geometry from READ to MEASURED** and does not consume
  a message. Currently the sizes come only from the binaries; `/dev/mq` files on
  2.6.31 expose only `QSIZE/NOTIFY/SIGNO/NOTIFY_PID`.
- `comm` semantics: run a binary named `/tmp/Xarracuda` and read
  `/proc/self/comm`. **Deliberately not named `Barracuda`** — a `/tmp/Barracuda`
  would satisfy `supervis`'s check and mask a real vendor death.
- `seedrng` behaviour: does busybox 1.36.1's `seedrng` credit the pool via
  `RNDADDENTROPY` on 2.6.31, or does its implementation call `getrandom()` and
  fail outright here? Seed dir in `/tmp`. **This is the most important untested
  assumption in the cert design.**
- `/dev/random` blocking behaviour and how long a 256-bit read takes from this
  pool.
- `grep` the `tuxedo` binary for `webuseraccountsenc.json` (§5.6).

**Proves:** the four assumptions the cert and IPC designs rest on.
**Revert:** `rm /tmp/*`. Precedent exists — the runtime survey left `/tmp` with
exactly its original four entries and 356K used. **MEASURED.**

#### Stage 2 DONE, 2026-09-06

`probe/stage2.c`, built with `/opt/musl-armel/bin/musl-gcc -Os -static`. Use
musl, not `arm-linux-gnueabi-gcc`: the gnueabi static binary is stamped
`for GNU/Linux 3.2.0` against a 2.6.31 kernel, and musl stamps no minimum.

**Queue geometry, now MEASURED rather than read out of the binaries.** Every
size the documents carried is confirmed:

| queue | maxmsg | msgsize | curmsgs |
|---|---:|---:|---:|
| `/Q_ServCmdRcver` | 32 | **404** | 0 |
| `/Q_ServCmdTrsmtr` | 32 | **556** | 0 |
| `/mqUI_Input_Queue` | 32 | 208 | 0 |
| `/g_mqSupervisionThreadIn` | 32 | 132 | 0 |
| `/mq_TuxAppVidRecEvent` | 100 | 580 | 0 |
| `/mq_VidRecWebAppEvent` | 20 | 60 | 0 |

`mq_getattr` consumes nothing and the queues were opened `O_RDONLY|O_NONBLOCK`.
One thing to read carefully: §1's note that `TCInterfaceInit` creates
`/Q_ServCmdRcver` with msgsize `0x11c` (284) is **not** contradicted — 404 is
the live attribute, so Barracuda's creation wins and TotalConnect's 284-byte
sends simply fit inside a 404-byte maximum. `mq_open` without `O_CREAT` takes
the existing geometry.

**`/dev/random` cannot produce a key, with numbers.**

```
entropy_avail before 133, poolsize 4096
got 16 of 32 bytes in 30.1s (151 EAGAIN, first at 0.0s)
entropy_avail after 16 (delta -117)
/dev/urandom control: 32 bytes in 0.000s
```

Half a key in thirty seconds, and the pool drained from 133 bits to 16 doing
it — it is being spent, not replenished. The `urandom` control rules out the
probe being the slow part. This is the assumption `tls/README.md` rests on and
it is now measured on the unit rather than inferred from `entropy_avail`
sampling.

#### MEASURED 2026-09-06: panel sessions are bound to the client's source IP

Found by building the stage-3 shim, handing it a session cookie obtained on a
workstation, and watching it take `401` from the build VM while that same cookie
worked from the workstation at the same moment.

Protocol held constant — both plain HTTP on port 80, byte-identical cookie:

| source | `/authenticated/index.html` | `/SimpleDebugger.interface/G.` |
|---|---|---|
| workstation `198.51.100.x` (created the session) | `302` → `/home.html`, recognised | `200`, streams |
| build VM `203.0.113.40` | `200`, 6553 B **login page** | `401` |

The panel simply does not know the cookie from the second address. Note the two
different denials for one cause: the `FormAuthenticator` path answers `200` with
a login page, the P13-gated push path answers `401`.

**Consequences.**

* **A shim cannot borrow a session — it must log in from wherever it runs.**
  For stage 3 as designed (`tuxweb` on the panel, talking to Barracuda over
  loopback) the session comes from `127.0.0.1` and the problem does not arise.
  It surfaced only because the shim was being exercised from a third host,
  which is not where it will live.
* **`ha-tuxedo-touch` must log in from the host that will use the session.** A
  cookie obtained on one machine does not work from another.
* A real if modest security property: a stolen cookie is useless from another
  address. Belongs in `tls/THREAT-MODEL.md` next to what TLS does and does not
  fix.

**Inferred, not read:** the binding is *presumed* to be on source address
because that is the only variable that changed. The field holding it has not
been located in the binary.

#### Stage 3 legacy shim: WORKING 2026-09-06, off-panel

`tuxweb --shim-login <host:port> <user> <pwfile> <bind>` logs in itself, opens
the vendor push stream, and re-serves it. Run on the build VM against the live
panel, a client pointed at the shim received:

```
HTTP/1.1 200 OK          Server: present and EMPTY      Connection: Close
boundary="EH912ZZ"       18 opening / 18 close delimiters
17 statusMessageText frames, 8 carrying live alarm state
  Client Connected
  0:504:1:P1  H:1:0:3:3          the registration frame
  0:-1:1:P1  H:1:0:3:3           x3, the fillers
  0:21:1:fe:<0xFE>1Ready To Arm:2
```

Every vendor quirk `conformance.py` asserts is reproduced, including the
RFC 2046 violation of closing every part, and the frames carry real panel state
rather than replay. That is the compatibility promise of §2.5 demonstrated
against the live panel, with Barracuda untouched.

It logs in from wherever it runs, which is required rather than tidy — see the
source-IP binding above. The password is read from a file so it never reaches
`ps`; the binary never takes it on the command line.

#### Running ON THE PANEL, 2026-09-06

Cross-compiled `arm-unknown-linux-musleabi` (866 KB, static, EABI5), copied to
`/tmp/tuxweb`, and run as
`--shim-login 127.0.0.1:80 lewis /tmp/pw 0.0.0.0:8081`. It logged in over
loopback — so the source-IP binding is a non-issue where the shim actually
lives — and served a client on the LAN:

```
HTTP/1.1 200 OK   Server: empty   Connection: Close   boundary="EH912ZZ"
12 opening / 12 close delimiters
12 status frames, 8 carrying live alarm state
  0:21:1:fe:<0xFE>1Ready To Arm:2   0:18:1 P1  H:2   0:-1:... x3
```

Barracuda untouched, nothing written outside `/tmp`, panel at 0 restarts
throughout, revert was `pkill`.

#### AND IT IS A SECURITY REGRESSION AS BUILT — the shim is UNAUTHENTICATED

The test client presented **no credential** and received live alarm state. P13
gated Barracuda's push path this morning precisely to stop that; the shim holds
one authenticated upstream session and re-serves it to anyone who can reach its
port. On a spare port for a timed test that is contained — the process was
stopped and `:8081` confirmed closed immediately after — but it must not ship
this way, and it would be an easy thing to leave running by accident.

**FIXED and verified on the panel the same day.** The shim now requires a token
of every client, set with `TUXWEB_TOKEN`, accepted as
`Authorization: Bearer <tok>` or `Cookie: tuxweb_token=<tok>`, compared in
constant time. Measured on the live panel:

| client | result |
|---|---|
| no credential | **401**, 0 frames |
| wrong token | **401**, 0 frames |
| correct `Authorization: Bearer` | 200, 9 frames, 4 with alarm state |
| correct `Cookie: tuxweb_token=` | 200, 4 frames, 4 with alarm state |

The denial is a real `401` with `Content-Length: 0` and an immediate close, not
a 200-with-page — the shape P13's design note argues for, because a stream
decoder reads a 200 body silently to EOF and hangs.

**Why a token rather than the vendor session:** the shim cannot validate a
client's panel session. Sessions are bound to the source IP, so a cookie the
client obtained from its own address is not verifiable by the shim from the
panel's. §4.10 already anticipates a token-gated stream; this is that.

Running with no token set is still possible and prints a loud warning naming the
bind address, because an open alarm feed should never be quiet about it.

**Session renewal: VERIFIED ON THE PANEL, 2026-09-07** — it fired by itself
during the stage-3 soak, which is the one way this was never going to be
staged. The panel expired the shim's session after roughly three hours; the log
shows `shim: upstream 401 -- session expired, logging in again`, and a
subscriber connecting afterwards is served `200` with 20 frames including
`0:21:1:fe:þ1Ready To Arm:2`. No re-login failure, and the process is the same
pid it started as.

One trap in reading that: the first probe after the renewal came back empty and
looked like a failure. It was not — the re-login is a full HTTP round trip on a
2009 CPU, and a client that gives up in 14 seconds disconnects before it
finishes, which the shim then reports as `1 subscriber(s) dropped`. A patient
client gets the frames. A short timeout here would have recorded "renewal
fired but produced nothing", which is the opposite of what happened.

**Previously verified under emulation, 2026-09-06.** The shim keeps the
credentials, and on an upstream `401` it logs in again once and retries; on an
upstream drop it reconnects with a bounded, spaced backoff (6 attempts,
1/2/5/10/20/30 s) because **every reopen re-registers and registering flushes
the panel's reply queue**, so a tight retry loop would be actively harmful. With
a bare cookie and no credentials it fails honestly instead of pretending.

Forcing a `401` was the problem. Logging in from another host does not
invalidate the shim's session, so the earlier guess that a new login voids prior
ones is unsupported and stays that way. What does invalidate it is restarting
Barracuda — free under emulation, and P13's gate runs in `EhDir_service` before
any IPC, so an emulated server rejects a stale cookie exactly as the panel does.
`emu/renewal-test.sh` does it end to end:

```
client before                     200 OK, 414 B, 1 frame
barracuda restarted               the shim's cookie is now worthless
shim: upstream ended (closed)
shim: upstream open failed (Connection refused); retry 1/6 in 1s
shim: upstream open failed (Connection refused); retry 2/6 in 2s
shim: upstream open failed (Connection refused); retry 3/6 in 5s
shim: upstream 401 -- session expired, logging in again
client after                      200 OK
re-login failures                 0
```

So the backoff is real (three spaced retries while the server was down, not a
tight loop) and the renewal is real. The remaining gap is narrow and worth
stating: this is a *restarted server*, not a session the panel timed out on its
own, and under emulation there is no `/tuxedo`, so "0 frames" after renewal
means the rig has no alarm state to carry, not that renewal served nothing.

**Fan-out: DONE and verified on the panel.** One upstream subscription is now
shared by every subscriber, which matters to the panel and not just to
throughput — each registration flushes the reply queue, so a subscription per
client would mean a flush per client. Measured with four simultaneous clients:

```
client1   200 OK   16 frames, 2269 B
client2   200 OK   16 frames, 2269 B     identical -> one shared stream
client3   200 OK   16 frames, 2269 B
no-token  401       0 frames,   77 B
```

Accept and authenticate happen on a separate thread, so a client that connects
and then says nothing cannot stall the stream, and a subscriber whose write
fails is dropped rather than allowed to block the rest. The shim holds no
upstream subscription at all while nobody is listening.

This also retires the single-client serialisation that misled me twice — once
looking like a broken token gate, once like a failed reconnect.

#### Pointing a consumer at the shim: proxy done, one blocker left

The shim now passes everything that is not the push stream through to Barracuda
(`src/proxy.rs`), which is what lets a consumer name **one** host. Verified on
the panel, all three through `:8081`:

| step | result |
|---|---|
| log in through the shim | session obtained |
| push stream with that session, **no token** | `200`, 16 frames, 8 with live alarm state |
| REST `GetSecurityStatus` | `302 -> https://203.0.113.5:443/...` |

The push result matters: the shim validated the client's **real panel session**
rather than a side-channel token, which it can do precisely because everything
reaches Barracuda from loopback. Logging in through the shim binds the session
to `127.0.0.1`, and every later request through the shim arrives from there too.

**The blocker is that same property.** The panel forces TLS on the REST
namespace (§5), so a plain-HTTP consumer gets a `302` to `https://panel:443`,
which the shim proxies faithfully — that part is correct behaviour, not a
defect. But **a consumer that follows it leaves the shim**, and its next request
reaches Barracuda from the consumer's own address carrying a session bound to
loopback, which the panel will reject. Mixing the two paths breaks the session
in a way that looks like a random logout.

**And the shim cannot serve that namespace itself.** Measured, all four
listeners, one authenticated `GetSecurityStatus`:

| listener | result |
|---|---|
| `http :80` | `302 -> https://…:443` |
| `http :6280` | `302 -> https://…:443` |
| `https :443` | `200`, real result |
| `https :9443` | `200`, real result |

So it is the scheme, not the credential — the redirect happens with full
authentication, and neither plaintext listener is a way round it. Proxying REST
therefore requires the shim to speak TLS *to Barracuda*, and that is the part
that does not work: **Ubuntu's OpenSSL 3 cannot complete a handshake with the
panel even at `SECLEVEL=0`** (cipher `0000`, no connection), and rustls is
stricter than OpenSSL, not laxer. Talking to this TLS needs an old stack, which
is the opposite of the project's direction.

**So the wholesale swap is off, and a split configuration is the answer:**

| traffic | endpoint | state |
|---|---|---|
| login + REST commands | panel `:443` directly, as today | unchanged |
| push stream | the shim, gated by a token | working now |

Each side keeps a session bound to the address that created it, so nothing
breaks: the consumer's own session for REST, the shim's loopback session for the
stream. The shim's session-validation path stays useful for clients that *do*
reach it through the proxy, but the token is what a split consumer will use.

**What this needs is a consumer-side change, not more shim.**
`ha-tuxedo-touch` would have to accept a separate push endpoint and token rather
than deriving the stream URL from the panel host. That is a change in that
repository and Lewis's call.

**No TLS termination in this mode** yet; the TLS listener is the binary's other
mode. Fan-out matters beyond convenience — each upstream registration makes the
panel flush its reply queue, so one shared subscription is strictly better than
one per client.

### Stage 3 — `tuxweb` as a TLS reverse proxy, spare port

**Change:** one new binary, run by hand on port 8443. Barracuda untouched and
still serving 80/443/6280/9443.

**Do:** `tuxweb --mode=proxy --port=8443`. It terminates modern TLS, serves the
new UI shell and the new API, and satisfies every request by talking to Barracuda
over loopback. It consumes the vendor push stream as a client
(`GET /SimpleDebugger.interface/G.` on `127.0.0.1:80`) and re-serves it as both
the new token-gated stream and the legacy shim.

**This stage exists because of blocker B1.** The read path cannot be shared, so
all the gradualism has to happen here: TLS, certificates, auth, tokens, the API
shape, the UI and the HA migration are all exercised and de-risked with the
vendor's IPC still doing the work.

**Proves:** rustls handshakes from real clients on the real LAN; the new API and
UI work; the legacy shim is byte-compatible with what HA already consumes.
**Revert:** `kill`. Nothing on disk changed outside `/tmp`.
**Known cost:** our push client is a second EH client, and registering flushes
the reply queue (§2.5). Same as running `tuxedo_push.py`.

#### Stage 3 measured on the panel, 2026-09-06

`tuxweb --shim-login` ran on the panel with `TUXWEB_CHAIN`/`TUXWEB_KEY` pointed at
the owner-CA leaf already in `/opt/tuxedo/configuration/tls/`, listening on
`0.0.0.0:8443`, proxying to Barracuda on `127.0.0.1:80`. Against
`https://203.0.113.5:8443/SimpleDebugger.interface/G.` from the workstation:

| client | trust | token | result |
| --- | --- | --- | --- |
| Python `ssl`, `check_hostname=True` | owner root | yes | TLS 1.3 `TLS_AES_256_GCM_SHA384`, `200`, 8 frames |
| Python `ssl` | owner root | no | `401`, 0 frames |
| Python `ssl` | system roots only | - | handshake rejected, `CERTIFICATE_VERIFY_FAILED` |
| Python `ssl`, `server_hostname=wrong.example` | owner root | - | rejected, hostname mismatch |
| curl 8.19 (schannel) | owner root | yes | `200`, 8 frames |
| curl 8.19 (schannel) | owner root | no | `401` |

Two client families, so the result does not rest on one TLS stack.

TLS 1.3 with a current client is the whole point. Barracuda's own listener is
OpenSSL 1.0.1h and cannot be reached by an OpenSSL 3 client at any `SECLEVEL`
(3.6); the shim is the first path to this panel that a modern client can
negotiate at all. It gets away with proxying to a server it could not itself
speak TLS to because the upstream leg is plaintext over loopback.

`Sink` in `shim.rs` is the `Read + Write` enum that lets one accept loop serve
both plaintext and TLS; `proxy::read_head` and `proxy::forward` were made generic
over it rather than duplicated. `tls_from_env()` exits when `TUXWEB_CHAIN` and
`TUXWEB_KEY` are set but unusable - a shim that quietly fell back to plaintext
after being asked for TLS would be the same class of bug as the unauthenticated
stream in 4.9.

Stopped afterwards: `:8443` closed, `:80`, `:443`, `:6280` and `:9443` still
Barracuda's, no restart.

**Trap for the documentation, found here.** Windows `curl` is a schannel build.
`--cacert` alone fails it with `schannel: the revocation status is unknown`,
because a private CA publishes no CRL or OCSP and schannel treats unknown
revocation as fatal. `--ssl-revoke-best-effort` clears it. This matters more than
it looks: an owner who hits that error and cannot explain it is the owner who
reaches for `verify_ssl: false`, which throws away the reason for doing any of
this. Say it in the install instructions, next to `install-root`.

### Stage 4 — Cert lifecycle in production

**Change:** writes `/opt/tuxedo/configuration/tls/` for the first time. Everything
in §3 ships.

**Do:** `tuxedo-ca.py init-ca` on the workstation; issue a leaf with the IP and a
hostname SAN, `notBefore` backdated 48 h; push with `tuxedo-tls-push.py`, which
verifies by connecting back and asserting the served certificate matches;
`install-root` on each client; move HA to the stage-3 proxy endpoint with a
token; install the daily expiry check.

**Proves:** the full lifecycle — issue, install, reload without dropping the
listener, rollback, emergency self-sign, expiry warning — against real clients.
Proves the clock-skew workaround. Proves `install-root` is easy enough that
nobody reaches for `verify_ssl: false`, which would make the whole TLS effort
worthless.
**Revert:** `tuxedo-tls rollback`, point HA back at port 80. `tls/` is additive;
no vendor file was modified.

### Stage 5 — `supervis` compatibility rehearsal

**Change:** `mkdir /opt/webserver/vendor`; move the vendor binary to
`/opt/webserver/vendor/Barracuda`; install `tuxweb` at `/opt/webserver/Barracuda`
in **passthrough mode**: it does nothing but `execve` the vendor.

**Do:** restart via `supervis`'s own path. Watch `/proc/<pid>/comm`, `cmdline`,
fd count and the listeners.

This is a deliberately boring stage that isolates the riskiest unknown —
`supervis` acceptance — from the risky one. If `supervis` does not accept a
binary at that path, we find out with the vendor still doing 100% of the work.

**Proves:** `comm` matching; the exec chain preserves the basename; `supervis`
does not relaunch; the fd ceiling is not near.
**Revert:** move the vendor binary back to `/opt/webserver/Barracuda`, restart.
Two commands.

#### Stage 5 PASSED on the panel, 2026-09-06

`supervis` accepts it. Measured on the live unit with `emu/stage5-panel.sh`,
which reverts unconditionally from a `trap` and was run under `setsid` so a
dropped ssh session could not leave `tuxweb` in the boot path:

```
before   pid 1096  comm Barracuda  cmdline /opt/webserver/Barracuda  4/4
install  tuxweb at the vendor path, vendor moved to vendor/Barracuda
kill     pid 1096 -> 2806 in 2s          <- supervis relaunched it
after    pid 2806  comm Barracuda        <- the string supervis strcmp's
                   cmdline /opt/webserver/Barracuda
                   exe     /opt/webserver/vendor/Barracuda
                   14 fds, 4/4 listeners
t+5/10/15s  pid 2806 stable, 4/4         <- supervis did not fight it
revert   vendor restored, 4/4, verify-panel.sh clean, panel disarmed
```

`exe` pointing at `vendor/Barracuda` while `cmdline` still reads
`/opt/webserver/Barracuda` is the whole stage in one line: the exec happened,
and everything `supervis` looks at is unchanged.

**Why it was safe to try.** `supervis`'s check was read first, not assumed:
`processdir(dirent const*, char*)` builds `/proc/%s/stat`, scans to the `)` at
`0xbe28`, and `strcmp`s the extracted text — that is `comm`, and `comm` follows
the exec'd basename, which is still `Barracuda`. `launchBarracuda()` shells out
`"/opt/webserver/Barracuda &"`. Neither looks at the inode or the path of the
image. The exec chain, pid retention and the loud-failure path were rehearsed
under emulation first (`emu/stage5-test.sh`).

**Two relaunches of the 24-relaunch watchdog budget were spent.**

#### The first run of this test was a false negative, and the shape is worth keeping

It reported `NOTHING is serving -- supervis did not accept it`. Nothing of the
sort had happened: the original vendor process was still running and had never
even been signalled.

`pid_on_80` matched `readlink /proc/<pid>/exe` against `*/Barracuda`. The moment
the file at that path is replaced, a running process's `exe` reads
`/opt/webserver/Barracuda (deleted)` — the pattern stops matching, the function
returns nothing, `kill` killed nothing, and the wait loop returned in 0 s
because the old process still held all four ports. Every subsequent line
described a process that had never been replaced.

Two fixes, both of which make the test ask the real question: find the process
by **`comm`**, which is the predicate `supervis` itself uses, and wait for a
**different pid**, not for a port that never closed.

### Stage 6 — The IPC cutover, read-only, bounded window

**This is the irreversible-feeling one. It is the only stage requiring a booked
window and Lewis at the panel.**

**Change:** `tuxweb` stops exec'ing the vendor and instead opens the two queues.
It **receives** on `/Q_ServCmdTrsmtr` and **sends nothing**. It logs every 556-byte
reply raw, and serves the legacy shim from them.

Mandatory safety features, all in the binary before this stage runs:

- **Deadman exec.** A timer armed at startup, **hard 15 minutes, and in the
  cutover path it is NOT resettable** — corrected 2026-09-07 from a compiler
  warning: `Deadman::reset`, `trip` and `disarm` are implemented and unit
  tested but never called, and `cutover::run` only ever reads `has_fired()`
  and `remaining()`. This section used to say "resettable by an authenticated
  call", describing a capability the type has and nothing wires up. **The code
  is right and the sentence was wrong:** the cutover binds no port, so there is
  no authenticated channel to reset it from, and a window that cannot be
  extended does the deadman's actual job — hand the panel back if nobody is
  watching — strictly better. `TUXWEB_CUTOVER_SECS` is read from the
  environment *supervis* passes, which a shell cannot set, so plan on 900 s
  absolute from the moment the cutover starts. On expiry the binary closes its
  sockets and queues and
  `execve`s `/opt/webserver/vendor/Barracuda`. If anything goes wrong and nobody
  is watching, the panel returns to the vendor stack by itself. This is what
  prevents the 24-relaunch watchdog reset described in §1.2.
- **Startup fallback.** Any failure to open a queue, bind a port, or reach a
  steady state within the window → close and `execve` the vendor.
- **Never create a queue.** Open `O_RDWR` only; wait and log if absent (B4).
- **Reader thread does nothing but receive.** Flush-on-full (B5) makes a slow
  reader lose all 32 messages, not fall behind.
- `FD_CLOEXEC` on everything we open, so the exec hands a clean slate over.

**Proves — and this is the decisive test of the entire plan:** that a process
other than Barracuda, as sole reader, actually receives tuxedo's replies. Lewis
presses keys on the touchscreen; the log fills with 556-byte messages whose
`msgType` values match the 43 constants Barracuda's own dispatch compares.

It is no longer how we get the payloads. `reply-layouts.txt` decodes all 92
send sites and 26 msgTypes statically, so **the window now confirms the map
rather than discovering it** — and a disagreement between the two is itself the
result, with the capture right and the static read incomplete (`TRAPS.md` §1).
Expect only the relayed set unless keys are pressed that exercise more: the
captures so far carry 18, 21 and 504.

The runbook is `emu/stage6-panel.sh`, split into phases so the booked window
holds only the part that needs someone at the panel. `phase0` is read-only,
can be run days early, and already passes on the live panel except for the
staged binary.

#### The shim CANNOT be served from queue replies alone — corrected 2026-09-07

This section used to also claim the window proves "the legacy shim emits frames
matching the stage-0 corpus; HA's alarm state tracks the touchscreen." **It
cannot, and the reason is structural rather than a matter of effort.**

**Corrected an hour later, from the code rather than from the signatures.** The
first version of this section said three of the four builders need external
state. Reading the actual `bprintf` call sites in `gettuxedoIPCCommFunc` shows
it is **one**, and which one matters:

| builder | the extra field really is | from the reply? |
|---|---|---|
| `frame_filler(r)` | — | yes |
| `frame_typed(r, trailing)` | **`r.arg`** | **yes** |
| `frame_status(r, quick_arm)` | `getQuickArmStatus()` | **no** |
| `frame_registration(r, extra)` | `+0xaf`, `+0xb1`, `+0xb2`, `+0xb4` | **yes** |

The frames are built by `bprintf` with `":"` passed as an argument — the string
at `0x84f5c` — which is why the format strings look like `%d%s%d%s...`. The
reply sits at `sp+0x274` in that function, so `sp+0x274` is `session`,
`sp+0x27c` is `arg`, and `sp+0x282` is the state byte at `+0x0E`.

- **Status**, `'%d%s%d%s%d%s%x%s%s%s%d'` at `0xdb04`. The final `%d` is stored
  at `sp+0x20` from `r0` immediately after `bl getQuickArmStatus()` at
  `0xdac8`. So `quick_arm` is genuinely Barracuda's, and
  `getQuickArmStatus` reads a byte out of a table — `[0x55b990]` indexes
  `[0x55ba18]` — after calling `setQuickArmStatus()` to refresh it. Config
  derived, so probably reproducible, but not from the reply.
- **Typed**, `'%d%s%d%s%s%s%d'` at `0xda1c`. The final `%d` is
  `ldr r3,[sp,#0x27c]` — **the reply's `arg`**. `frame_typed`'s `trailing`
  parameter and `Reply::arg` are the same value.
- **Registration**, at `0xf638` — **resolved 2026-09-07, and every field comes
  from the reply.** A displacement scan finds nothing at `+0xaf..+0xb8` because
  the builder reads through a base pointing into the buffer; running the reply
  map's own interpretation over Barracuda instead gives the offsets directly.
  Against the buffer at `sp+0x274` it reads `ldrb [sp,#0x304]` = `+0x90`, takes
  the description with `add r6,r6,#0x91`, then `+0xaf`, `+0xb1`, `+0xb2` and
  `+0xb4`, pushing `r4` — the `":"` literal — between each. So the wire frame
  `0:504:1:P1  H:1:0:3:3` is
  `session : 504 : +0x90 : +0x91 : +0xaf : +0xb1 : +0xb2 : +0xb4`, i.e. current
  partition, partition description, panel CAL implementation, operation mode,
  total partitions, Z-Wave controller status. **`frame_registration` needs no
  Barracuda state**, so a replacement can emit a 504 from the queue message
  alone.

  Two things this corrected in `ipc.rs`. Its doc named *five* trailing values
  for a `[u32; 4]` and put the Z-Wave status first; and `frame_registration`
  took the third field from `r.arg`, which `Reply::parse` reads at `+0x08` —
  an offset `registerclient` **never writes**, so the frame carried
  uninitialised stack. `Reply::parse_504` and `Reply::registration_extra` read
  the right offsets, and a test now builds a real 556-byte 504 and asserts it
  reproduces the captured frame. The corpus test could not have caught this
  either: it rebuilds the `Reply` from the frame's own text, so it reproduces
  the frame whatever offsets the fields actually came from. `+0xb0` and `+0xb8`
  are written by `registerclient` but never read by the builder.

The corpus test could not have caught that: for the 4-field shape it builds
`Reply { arg: 0, .. }` and passes the trailing field separately, so it proves
the formatter faithful while leaving the two names looking independent.

The signature-level reading was not wrong about `frame_status`, but it
generalised from a parameter list to a conclusion about three builders when the
code said one. Parameters describe an interface; only the call site says where
the argument comes from.

This was hiding behind a passing test. `every_captured_frame_is_reproducible_from_its_fields`
checks 150 frames, but it works *backwards*: it splits a captured frame on `:`
and feeds the pieces back to the builder. That proves the builders are faithful
formatters. It says nothing about where the inputs come from, and it silently
assumes the reply text contains no `:` — an assumption that has never been
checked and is load-bearing for the split.

**Consequences:**

1. **Stage 6 stays log-only**, but for a smaller reason than first written: the
   status frame is the one that carries alarm state, and it is the one that
   needs `getQuickArmStatus()`. Serving typed and filler frames while silently
   omitting status would give HA a stream that looks alive and never reports
   arming, which is worse than going dark.
2. **The stage-7 blocker is narrower than it looked.** One value, from a
   config-derived table, not three unknowns.

### 5.12 `quick_arm` — ANSWERED AND VERIFIED ON THE PANEL, 2026-09-07

**A replacement can emit the status frame.** The chain is short and every link
is now read or measured:

```
/opt/tuxedo/configuration/quickarmstate      eight ints, fscanf "%d%d%d%d%d%d%d%d"
   -> setQuickArmStatus()  @0x2d420          into the array at 0x55ba18
   -> getQuickArmStatus()  @0x2d4e4          byte[0x55ba18 + partition - 1]
   -> the status frame's trailing field
```

`setQuickArmStatus` reads the file after
`validateCRCFileOnFileRead("…/quickarmstate", "…/quickarmstate_")`, and
`getQuickArmStatus` indexes the loaded array by the current partition, taken
from the byte at `0x55b990`.

Verified end to end on the running panel:

```
/opt/tuxedo/configuration/quickarmstate   ->  "2 0 0 0 0 0 0 0"
live frame from the shim                  ->  0:21:1:fe:þ1Ready To Arm:2
```

Partition 1 selects the first value, `2`, which is exactly the frame's trailing
field. **So stage 7's byte-compatible legacy shim is achievable**: read that
file and index it, which is what Barracuda does.

Two notes worth keeping. `quickarmstate_` **does not exist on this panel**,
although `setQuickArmStatus` passes it to the CRC validator — so the validator
tolerates a missing sidecar, and a replacement writing this file must not
assume one is required. And `fscanf` with `%d` is given eight destinations one
byte apart (`0x55ba18`, `+1`, `+2`, …), so each four-byte store overlaps the
next; the values happen to be small, and this is the vendor's bug, not ours.

#### The registration frame, and a correction to the reply layout

`CReceiverThread::registerclient()` @`0x13c2f8` builds the msgType 504 reply,
and reading it settles the registration extras and overturns something more
important.

It writes `session = 0` at `+0x00`, `msgType = 0x1f8 = 504` at `+0x04`, and
then:

| offset | value | from |
|---|---|---|
| `+0x90` | current partition | `GetCurrentPartition()` |
| `+0x91` | partition description, `strcpy`d | `GetPartitionDescription()` |
| `+0xaf` | CAL implementation | `GetPanelCalImplementation()` |
| `+0xb0` | quick-arm capable | `GetArmingModes() & 8` |
| `+0xb1` | operation mode | `GetOperationMode()` |
| `+0xb2` | total partitions | `GetTotalPartitions()` |
| `+0xb4` | Z-Wave controller status | `getZWControllerStatus()` |
| `+0xb8` | RIS supported | `isRisSupported()` |

So the registration frame's `1:0:3:3` extras are **in the reply after all**,
just not at `+0x0E`. Like `frame_typed`'s trailing field, they were only ever
missing from a decoder that looked in one place.

**The correction that matters: the 556-byte reply is a union, not a struct.**
`session` and `msg_type` hold for every message; everything after depends on
the type. `Reply::parse` puts the text at `+0x0E`, which is right for the
status path it was derived from and simply wrong for a 504 — that message has
nothing of interest there. `ipc.rs` now says so at the type.

**And the `:` question is answered, unhappily.** For a 504 the "text" is the
partition description, `strcpy`d straight out of `GetPartitionDescription()` —
an owner-settable partition name. So a partition named with a colon in it would
put a colon in the frame. The corpus test's assumption that the text contains
no `:` is therefore an assumption about *this panel's configuration*, not a
property of the protocol, and a replacement must not rely on it. It holds here
(`P1  H`), which is why 150 frames reproduced.

**Also unsettled, and it undermines the corpus test if wrong:** whether the
reply text can contain a `:`. The test splits captured frames on `:` and
assumes it cannot. Now that `sp+0x274` is known to be the reply, the text is at
`+0x0E` and what `/tuxedo` puts there can be read directly.

**Revert:** authenticated "fall back now" call, or wait for the deadman, or SSH
`mv` and restart. Three independent paths, one of them automatic.

**During this stage the web UI cannot arm or disarm** — we send nothing. The
touchscreen can, and does, throughout. That is the point.

### Stage 7 — The write path, in increasing order of consequence

Four sub-stages, each its own window, each with the deadman armed.

- **7a** — command 500 (`SERV_CLIENT_REGISTER`) with a non-zero `sessionId`, and
  501 to unregister. Proves we can drive the queue at all; expect the `504` reply
  frame (`registerclient` sets `r2 = 0x1f8`, **READ**), which matches the measured
  `0:504:1:P1  H:1:0:3:3`.
- **7b** — read-only commands: 5 (partition status), 12 (all zone current status),
  18 (home partition details), 17 (event log upload, paged). None of these change
  panel state.
- **7c** — console mode (19) with a benign keypress, and 502/503 (home/back). Note
  console keys are a real keypad; use a key that does nothing.
- **7d** — **arming.** 2 (`ARM_STAY`), then 3 (`DISARM`), then 1 (`ARM_AWAY`), then
  4 (`ARM_NIGHT`). Monitoring on test. Lewis at the panel. One command per attempt,
  verified on the touchscreen and in the push stream before the next.

A code-derived prediction to test at 7d, currently **untested on hardware**: the
REST path's `setarmwithcode` @`0x1afc8` hard-codes `sessionId = 0`, and both
`sltSendUserCodeAcceptedMsg` @`0x13c408` and `sltSendUserCodeDeclinedMsg`
@`0x13dbb4` return without sending when the stored `sessionId` is zero. **READ.**
That explains the measured absence of a VALID USER CODE frame on REST arms, and
predicts that a **non-zero** `sessionId` produces the confirmation frame. Test the
accepted path only; the declined path stays untested because a failed code
attempt has consequences on the panel.

**Proves:** functional parity for security operations.
**Revert:** per sub-stage, the deadman and the `mv`.

### Stage 8 — Retire the proxy and the plaintext stream

**Change:** `tuxweb` serves everything itself; the loopback proxy path is
removed. Port 80 becomes 301-only. `push.legacy_plaintext` defaults to false.
6280 and 9443 are not bound.

**Proves:** the vendor binary is no longer in the request path for anything.
**Revert:** re-enable proxy mode (the code is still there this stage), or `mv`
the vendor binary back.

### Stage 9 — Decommission

**Change:** remove the vendor binary from the built image; remove proxy mode and
the legacy plaintext flag from the source; decide HSTS (§2.6 says: only with a
hostname, only after two ACME cycles, short `max-age`, no preload).

Keep `/opt/webserver/vendor/Barracuda` on the *running* panel for at least one
more release even after it leaves the image. It costs 5.7 MB of 57 MB free and it
is the last non-reflash revert.

**Revert:** the previous image.

---

## 4.10 The consumer's contract, stated by the consumer

Everything in this section comes from the author of `ha-tuxedo-touch`, the
public HACS integration that consumes this panel, checked against their shipped
code rather than recalled. It is requirements, not speculation, and it settles
two questions this document had left open.

### 4.10.1 The push stream SHOULD require authentication

This document assumed requiring credentials on `/SimpleDebugger.interface/G.`
would be a breaking change and priced it as a compatibility cost. **It is not.**
Their stream client already sends the session cookie on every connection and
already treats 401/302 as an expired session with exactly one re-login:

```
push.py:447   cookie = await self._client.async_session_cookie()
push.py:463   headers={"Cookie": cookie},
push.py:468   if resp.status in (401, 302):   -> session expired, one re-login
```

So a replacement that *requires* auth on that path works against the integration
unchanged, with no version detection and no migration. **Decision: the
replacement authenticates the push stream.**

What that closes is real. Today the stream hands live alarm state -- armed,
disarmed, and the exit-delay countdown ticking down -- to anything on the LAN
with no credential at all (OQ-1, answered on hardware). That is the single most
useful signal in a house for anyone working out when it is empty.

### 4.10.2 Add a version / capability endpoint. This is the highest-value addition

`API_REV01` has **no version, model or firmware endpoint of any kind** --
established from the vendor's own `script/tuxapi.js`. The firmware string is
readable only on the unit's own screen.

That one absence makes every other improvement unusable to a public integration.
Probing an unknown endpoint to discover what you are talking to means sending
unhandled paths to a stranger's alarm panel, which no responsible integration
will do. So without it, a replacement can add the best capability in the world
and no client can ever call it.

With it, every addition becomes optional and safely detectable: ask once at
setup, use the better path when present, fall back silently when absent. In the
consumer's words, it converts *"a fork nobody can support"* into *"a superset
anyone can adopt"*.

**Decision: the replacement serves a version/capability endpoint, and it is a
release-one requirement rather than a nice-to-have.**

### 4.10.3 Three long-standing asks that the architecture resolves for free

All three were consequences of Barracuda's design, not the panel's. A server
reading the queues directly does not inherit any of them:

| Ask | Why it disappears |
|---|---|
| The `"Not available"` status cache -- the defect that started this project | There is no cache to be empty if you read the queue |
| `PanelIsTalking` exposed over REST | The link state is in hand, rather than a global inside a closed binary |
| Did the panel ACT, not merely receive the command | The queue carries the answer. Barracuda is what discards it and returns `"Command sent sucessfully"` regardless. This one lets the integration delete its `assumed` state, and is the most valuable of the three |

**Additive only.** New endpoints alongside the old, same frames on the stream,
same paths for the existing calls.

### 4.10.3b Fixture P0, captured: the close-delimiter is emitted after EVERY part

MEASURED 2026-09-06, raw socket, port 80, no credential, 2616 bytes.

Response headers:

```
HTTP/1.1 200 OK
Server:                                       <- empty
Connection: Close                             <- on a long-lived stream
Cache-Control: no-store, no-cache, must-revalidate
Content-type: multipart/x-mixed-replace;boundary="EH912ZZ"
```

Body framing, per frame. Every line below is terminated by CRLF, and the blank
line after the part header is CRLF alone:

```
--EH912ZZ                                          CRLF
Content-type: text/plain                           CRLF
                                                   CRLF   (empty line)
['ud','SimpleDbgServer2ClientIntf','statusMessageText',["..."]]   CRLF
--EH912ZZ--                                        CRLF   <- CLOSE delimiter
```

The trailing `--` on the last line is the point: it is the multipart **close**
delimiter and it is emitted after every single part.

In the capture: **19 opening boundaries and 19 close delimiters.**

**This is not valid RFC 2046.** `--boundary--` is the *close* delimiter and means
the multipart body has ended. The vendor emits it after every part, so a strict
multipart parser reads the first frame, concludes the stream is finished, and
stops -- which is why a hand-rolled scanner works here and a conforming library
does not.

**Consequence for the replacement:** this framing must be reproduced exactly.
Emitting a standards-correct stream -- one close delimiter, at the end -- is
precisely the kind of "fix" that looks like an improvement and breaks every
client written against the vendor. It belongs with `"Sucess"` in
`quirks_to_preserve`.

`Connection: Close` on a stream the panel then holds open indefinitely is a
second quirk in the same family, and is likewise reproduced rather than
corrected.

(The raw capture is deliberately not committed: push frames can carry the LAN
device inventory -- hostnames and IPs of everything the camera scan finds -- and
this repository is public.)

### 4.10.4 Invariants that must not move

Pinned by the consumer's test suite as of 2026-09-06. Changing any of these
breaks a shipped integration:

```
0:21:1:fe:<0xFE>1Ready To Arm:2      and the id -1 record in BOTH shapes
raw 0xFE / 0xFF immediately before the display text   <- their discriminator
field 2 = panel status code, -1 when the ECP link is down
/system_http_api/API_REV01/AdvancedSecurity/{ArmWithCode,DisarmWithCode}
```

Plus the vendor's misspellings and asymmetry, which are part of the contract:
`{"Status":"Sucess","Result":{"Response":"Command sent sucessfully"}}` for arm
and `{"Status":"Sucess","Result":{"Result":"..."}}` for disarm. Arm and disarm
use **different inner keys** and both spell `Sucess` wrong. A rewrite that
tidies either breaks every client on vendor firmware.

The `-1` marker deserves specific care: it is how a dead ECP link becomes
visible at all. It is produced by `/tuxedo` rather than Barracuda, so it should
survive replacement for free -- but losing it silently would reintroduce a defect
the integration has already shipped and fixed once.

### 4.10.6 The capability endpoint, settled

    GET /system_http_api/API_REV01/GetCapabilities

    stock:  404  {Status:"Not Found"}     MEASURED, with AND without a session
    custom: 200  application/json

    {
      "contract": 1,
      "firmware": "tuxweb/0.1.0",
      "panel_model": "TUXW",
      "capabilities": ["panel_link_state", "command_result", "status_refresh"]
    }

**Inside `API_REV01`, not outside.** MEASURED on the live panel while it was
still running stock: an unknown endpoint there returns a 20-byte
`{Status:"Not Found"}`, while unknown *top-level* paths 302 to a trailing-slash
variant. `/Config/` only 404s because it already carries the slash. So the
vendor namespace is the clean option and outside it is the messy one -- the
opposite of what both of us assumed.

A GET against an endpoint that exists returns `405 {Status:"Method Not Allowed"}`,
so 404 / 405 / 200 are three distinguishable answers for free.

**The endpoint is session-OPTIONAL, and the reason is structural rather than
aesthetic.** Session-required would make custom firmware answer 401 without a
session. The integration treats 401 as an expired session and responds with a
re-login -- so capability detection would become a path from "check what this
panel supports" to "spend a login attempt", on a device where three refused
logins disable every web account and the count survives a reflash.

Stock structurally cannot do that: MEASURED, an unknown endpoint returns 404 with
or without a session, never 401 and never 302. Session-optional makes custom
match, so the property holds on every firmware rather than on one. The
fingerprinting cost is accepted and is small next to what the panel already
announces -- hostname `Tux<MAC>`, a Resideo OUI, six open ports and a
distinctive login page.

**Hard constraint, recorded because a client keys its silent path on it:** 404
must remain the absence answer permanently. A future build answering anything
else for an unsupported capability query is a breaking change. `200` with an
empty capability list is fine; anything else is not, and must be flagged before
it ships.

`contract` is an integer that moves only when the SHAPE of this document changes
incompatibly, never for feature changes. Clients branch on `capabilities`, never
on `firmware` or `contract`; the list is unordered and unknown strings are
ignored. Called once at setup and cached.

Reference copy lives in `docs/wire-contract.json` in `ha-tuxedo-touch`, marked
NOT PRESENT ON ANY FIRMWARE YET.

### 4.10.7 Console mode arrives free

Established while testing a `/tuxedo` patch that did not work (see
TUXEDO-VIRTUAL-CONSOLE-BUGS.md): the two-line keypad display is emitted by
`/tuxedo` as reply message **type 20**, and Barracuda's reply dispatcher
`gettuxedoIPCCommFunc` has no case for 20 among the 42 types it handles. It is
discarded at the edge, not withheld by the alarm application.

A replacement reading `/Q_ServCmdTrsmtr` directly receives type 20 with no
additional work. That is a far richer status source than `GetSecurityStatus` --
the actual keypad display text -- and it costs nothing beyond not throwing it
away.

Reading it is passive. **Sending keystrokes is a separate write path
(`apl_sendEcpConsoleModeData`, keys carried pipe-delimited in `pID`) and is a
control surface equivalent to standing at the keypad.** If the replacement
exposes it at all, it needs the same treatment as arm/disarm, not the treatment
of a diagnostic read-out.

### 4.10.5 Why compatibility is a hard requirement, not courtesy

Almost no user of `ha-tuxedo-touch` will run this firmware. If the replacement
diverges, the integration must detect which server it is talking to and carry two
code paths across the alarm-critical surface -- and only one of them can ever be
tested against real hardware, because there is one panel. Two code paths where
one is untestable is worse than either alone.

---

## 5. What is still unknown

Ordered by how much the plan changes if the answer goes the wrong way.

### 5.1 Can any process but Barracuda actually receive tuxedo's replies?

**The one that decides everything.** Everything above assumes that a process
holding `/Q_ServCmdTrsmtr` as sole reader gets the reply stream, and that
`/tuxedo` does not gate delivery on something Barracuda-specific we have not
seen. The evidence for it is strong but entirely code-derived: the reply
`osal_MqSend` calls take no client identity, and `/TotalConnect` writes the
command queue unconditionally (**READ**) — but no third-party message has ever
been observed on this bus, in either direction. The mapping's summary called this
"empirical"; the review is right that it is not, and this is the claim the whole
project rests on.

**Cheapest experiment:** stage 6, in its read-only form, with the deadman armed —
about 15 minutes with Lewis at the panel. There is no cheaper version, because
the single-reader rule (B1) means it cannot be done alongside a running
Barracuda. Do stages 2 and 5 first so that when this fails, it fails for a reason
we have already eliminated.

If it goes wrong: the plan degrades to `tuxweb` permanently in stage-3 proxy
mode. That still delivers modern TLS, real certificates, an authenticated push
stream and a new UI — the vendor binary survives as an IPC shim behind loopback.
Materially worse, but not a dead end, and it is why stage 3 comes first.

### 5.2 `supervis`'s poll period, and the size of the stage-6 window — ANSWERED, 2026-09-06

**Units are seconds, and the number that matters is 5, not 600.**

`ArmSWTimer(void* timer, int secs, long long, bool repeating)` writes its `int`
argument straight into `it_value.tv_sec` of the `itimerspec` it hands
`timer_settime` — `str r7, [fp,#-0x2c]`, with the struct based at `fp-0x34`, so
that slot is `tv_sec`. The `bool` selects repeating: set, and `it_interval` is
filled too; clear, and the timer is one-shot and its handler re-arms it.

`main` creates **seven** timers, and the `0x258` one is not the interesting one:

| timer | handler | period |
|---|---|---|
| six app supervisors | `RelaunchBarracudaHndlr`, `relaunchTuxedo`, `RelaunchTcHndlr`, `RelaunchVrecHndlr`, `RelaunchFtpcliHndlr`, `RelaunchAudioappHndlr` | **5 s**, one-shot, re-armed |
| housekeeping | `SupervisTimeout` — `get_num_fds`, `SuperViseMemoryUsage` | 600 s |
| watchdog kick | `wdg_init`'s handler | **1 s, repeating** |

So `0x258` is a ten-minute *housekeeping* pass, and **Barracuda is checked every
5 seconds**. The earlier framing of this question — 0.6 s versus 10 minutes —
had the wrong timer in view.

**Corroborated by stage 5**, which is the point of having both: killing
Barracuda produced a new pid within 2 s, impossible on a 600 s poll and
consistent with a 5 s one-shot caught partway through.

**Stage 6 therefore has a ~5 second window**, not ten minutes. The deadman has
to be sized against that.

**The memory ceiling, which the question also asked for as a number.** It is a
proportion, not a constant. `__static_initialization_and_destruction_0` computes
all four limits from `SYSTEM_TOTAL_MEMORY` at startup:

| global | value |
|---|---|
| `SYSTEM_MAX_ALLOWED_MEMORY` | 95% of total — and `SuperViseMemoryUsage` compares **system-wide** usage against it, not per-process |
| `BARRACUDA_MEMORY` | **25% of total** |
| `TUXEDO_MAX_MEMORY` | 75% of total |
| `VIDAPP_MAX_MEMORY` | 75% of total |

On this panel `MemTotal` is 126016 kB, so **`BARRACUDA_MEMORY` is about
31500 kB (~30 MB)**. Measured alongside it: Barracuda's current RSS is 6104 kB
and `/tuxedo`'s is 32924 kB. A ~1 MB Rust process has roughly thirty times the
headroom it needs, which is now a number rather than a hope.

### 5.3 Does killing Barracuda risk the hardware watchdog? — ANSWERED NO, 2026-09-06

It cannot. Barracuda has no code that could open or close it.

- `wdg_init()` @`0xb590` does `open("/dev/watchdog", O_RDWR)` **once**, stores
  the fd in a global, `ioctl`s it to enable, and arms a kick timer with
  `ArmSWTimer(t, 1, 0, 0, 1)` — **1 second, repeating** (the `bool` sets
  `it_interval`). The only close is in `wdg_deinit()`, a separate teardown path.
- Barracuda contains **zero** watchdog symbols and **zero** occurrences of the
  string `/dev/watchdog`. `supervis` has three symbols
  (`wdg_init`, `wdg_deinit`, `WdgKickHndlr`) and exactly one such string.

So Barracuda's fd 4 is inherited across the `system("/opt/webserver/Barracuda &")`
launch and nothing more. Closing one descriptor of an inherited open file
description does not close `supervis`'s, and Barracuda has no way to ask.
Upgraded from **INFERRED** to **READ**: the previous wording rested on "should
not", and the thing that removes the doubt is that the code to do it does not
exist in that binary.

Unresolved side note kept for the record: the extracted `config.gz` says
`# CONFIG_WATCHDOG is not set` yet `/dev/watchdog` exists and is kicked once a
second. The config is probably stale or mismatched; it was not reconciled.

### 5.4 Does `comm` follow the basename? — ANSWERED YES, 2026-09-06

**MEASURED**, and without starting a single new process: every process already
running answers it.

```
  PID    EXE                        STAT-FIELD-2   matches basename
  902    /supervis                  supervis       yes
  915    /tuxedo                    tuxedo         yes
  1074   /opt/webserver/Barracuda   Barracuda      yes
  1112   /TotalConnect              TotalConnect   yes
  842    /usr/sbin/dropbear         dropbear       yes
```

So a replacement installed at `/opt/webserver/Barracuda` presents `comm` as
`Barracuda` and satisfies `supervis`'s lookup. The install-path rule in §1.2
stands on measurement now, not on kernel semantics.

**The proposed experiment would have failed, and the reason matters more than the
answer.** It said to read `/proc/self/comm` — **that file does not exist on this
kernel.** `/proc/<pid>/comm` was added in Linux 2.6.33 and this panel runs
2.6.31. Every read returns `No such file or directory`, including for the
reading shell's own PID. **MEASURED.**

The comm value lives only in field 2 of `/proc/<pid>/stat`, inside parentheses —
which is exactly where `supervis`'s `processdir` @`0xbd68` reads it, so the
disassembly was right and the proposed test was wrong.

**Carry this forward:** any tooling written against `/proc/<pid>/comm` silently
returns nothing here rather than failing loudly. Parse `/proc/<pid>/stat`
instead. Note the process name can itself contain `)`, so match the LAST `)` in
the line, not the first.

(Two further traps found while testing this, both worth avoiding: busybox
dispatches on `argv[0]`, so a copy under an unrecognised name exits immediately
with `applet not found` and is useless as a test vehicle; and a job backgrounded
inside a non-interactive `ssh` command dies as the session tears down — the same
thing that silently swallowed an earlier `reboot`. Use `setsid`, or run in the
foreground from a second connection.)

### 5.5 Does busybox `seedrng` credit entropy on 2.6.31? — ANSWERED NO, 2026-09-06

It runs, it does not fail, and it **never credits**. Measured on the panel with
busybox 1.36.1, seed dir `/tmp/seed`, three consecutive runs:

```
entropy before: 58
run 1 (-n)   Saving 2048 bits of non-creditable seed for next boot
             entropy_avail 58
run 2        Seeding 2048 bits without crediting
             Saving 2048 bits of non-creditable seed for next boot
             entropy_avail 58
run 3        Seeding 2048 bits without crediting
             entropy_avail 58
```

The reason is in `miscutils/seedrng.c`. It first tries
`getrandom(seed, len, GRND_NONBLOCK)`; that is ARM syscall 384 and this kernel's
ceiling is 363, so it is `ENOSYS`. It then decides creditability with
`poll(/dev/random, 0)` — readable *right now* or not — and with the pool at 58
bits that returns 0. `GRND_INSECURE` fails the same way, so it falls back to
reading `/dev/urandom` and marks the seed non-creditable. Every path leads to
`entropy_count = 0`.

**This is the good outcome, and better than the question assumed.** The worry
was that `seedrng` would fail outright. Instead it degrades safely: it still
mixes a seed across boots, and it never inflates `entropy_avail` with material
drawn from the same weak pool. It cannot rescue on-device key generation, and it
does not lie about the pool either. Workstation generation stays the only
supported path — now for a measured reason rather than a suspected one.

Note the interaction with §3's `/dev/random` measurement: `poll()` returning 0
is not a busybox quirk, it is the pool genuinely being empty. The two results
are the same fact seen from two directions.

### 5.6 Does `/tuxedo` read `webuseraccountsenc.json`? — ANSWERED YES, 2026-09-06

§1.6 has v1 abandoning the vendor's web-account store. It reads **and writes**
it, from five named functions, so abandoning the store is not a Barracuda-only
decision:

| function in `/tuxedo` | what the name says it does |
|---|---|
| `readWebUserAccSetupJSONFile(strAccountSettingsForJSON*)` | reads it into a struct |
| `createWebUserAccSetupJSONFile(strAccountSettingsForJSON*)` | writes it |
| `encodewebUseraccJsonFile()` | writes the `_enc` and `_sec` forms |
| `isWebUserAccSetupJSONFileEncPresent()` | existence check |
| `isInitWebUserAccSetupJSONFileEncPresent()` | existence check at init |

`/tuxedo` also touches `/opt/tuxedo/configuration/webuseraccounts.json`, the
`_sec` variant, and `/tmp/webuseraccountsenc.json`.

**Consequence for v1.** `/tuxedo` is the component we are keeping. If the
replacement stops maintaining this file, `/tuxedo` keeps reading whatever is
left there, and the two components' views of who has an account diverge
silently. Either the replacement maintains the file in the vendor's format, or
§1.6 has to say what happens to `/tuxedo`'s copy — it cannot just be dropped.

**How this was checked, because the first attempt said the opposite.** Finding
the string and searching the file for a word equal to its address returned
"referenced nowhere" — for Barracuda too, which manifestly does read the file
from `readUserNamePasswordFromJSON`. That impossible control result is what
exposed the bug: the search matched the substring `webuseraccounts`, while the
literal pool holds the address of the start of the whole path string. Walk back
to the preceding NUL first. `q56.py` runs Barracuda as the control for exactly
this reason.

### 5.7 Is `/tuxedo` an HTTPS client of a Tuxedo REST API?

The review found `/tuxedo` links `libcurl.so.4`, `libssl.so.1.0.0` and
`libcrypto.so.1.0.0`, imports `curl_easy_*`, and carries
`https://%s/system_http_api/API_REV01/System/Tuxedo/ZwaveSync/zwavesyncinit`
at `0x5ff75c` beside `TUX_IP`, `TUX_HTTP_PORT`, `findEnrolledPrimaryTuxedo` and
`TuxedoDetails_sec.json`. **READ.** So the mapping's "MEASURED: `/tuxedo` does not
talk to Barracuda over TCP at all" — a universal negative drawn from one
`netstat` on an idle panel — is not established, and is downgraded to
**INFERRED** here.

Whether that address can ever be this unit's own is undetermined (no `127.0.0.1`
or `localhost` string exists in the binary). If it can, then an ECDHE-ECDSA-only
server behind a new private CA has an unexamined client: OpenSSL 1.0.1h via
libcurl, whose trust store and verify settings nobody has looked at. Candidate
breakage: Tuxedo-to-Tuxedo Z-Wave sync.

**Checked on the panel, 2026-09-06: no peer, so the path is not live here.**
Neither `TuxedoDetails.json` nor `TuxedoDetails_sec.json` exists in
`/opt/tuxedo/configuration`. This is a single-panel installation, so the
Tuxedo-to-Tuxedo Z-Wave sync client never runs and cannot be broken by a new
private CA on this unit.

That closes it *for this panel* and not in general: the client code is still
there, so an owner who enrols a second Tuxedo would exercise an OpenSSL 1.0.1h
libcurl client whose `CURLOPT_SSL_VERIFY*` settings nobody has read. The
follow-up is unchanged and now conditional — if a peer is ever enrolled, read
those options before assuming the CA change is transparent.

Seen again while reading that config, and already covered: the
`DISCOVERY_SETTINGS` block in `Tuxedo.json` holds a `SHARED_KEY` and a
plaintext `localadministrator,<password>` pair beside the camera inventory.
`CONFIG-EXPOSURE.md` §"Upgraded" documents it; this is a second sighting on the
live unit, not a new finding. Values are deliberately not reproduced anywhere in
this repository.

### 5.8 Client acceptance of a private root for an IP-literal SAN - PROGRAMMATIC CLIENTS ANSWERED, 2026-09-06

Decides whether the documentation should push owners toward a hostname plus local
DNS rather than the bare `203.0.113.5` they use today, and whether a self-signed
leaf with `CA:FALSE` in the trust store would have been enough (§3.4).

Answered for the clients that matter to Home Assistant, against the stage-3
listener. The leaf carries `CN=203.0.113.5` and one SAN, `IP Address:203.0.113.5`.
Python `ssl` with the owner root as its only CA and `check_hostname=True` accepts
it by IP; the same context connecting with `server_hostname="wrong.example"` is
rejected for hostname mismatch, so name verification was genuinely running and
the IP SAN is what matched. curl 8.19 (schannel) accepts it too, given
`--ssl-revoke-best-effort` - see the revocation trap under stage 3.

Still open for browsers: Chrome and Firefox apply their own rules to IP SANs and
to privately rooted chains, and neither has been tried. The browser result is
what decides the hostname-plus-local-DNS recommendation; the programmatic result
only settles that the integration does not need one.

### 5.9 Can Home Assistant set an Authorization header on a long-lived multipart stream? — ANSWERED YES, 2026-09-06

It can, and it now does. `TuxedoPushStream._async_stream_once` sets
`headers["Authorization"] = f"Bearer {self._push_token}"` and a
`tuxweb_token=` cookie alongside the panel session cookie, on the same
`aiohttp` request that holds the stream open. Verified end to end rather than by
reading: `tests/ha/test_options_flow.py::test_the_entry_loads_and_streams_from_the_relay`
loads the integration, points the stream at a fake panel and asserts the
captured request carried both forms.

**So the query-parameter token form is optional, and should not be built.** A
token in a URL lands in access logs and `Referer` headers; there is no reason to
accept that cost now that the header form is demonstrated on the actual client.
The shim already gates on either (`shim.rs::presents_token`).

### 5.10 The reply payload beyond `+0x0E` — ANSWERED STATICALLY, 2026-09-07

It did not need the window. Every builder is a named function in `/tuxedo` that
passes `0x22c` to `osal_MqSend`, so the layouts can be read out of the binary,
and the stage-6 capture becomes confirmation rather than discovery.

`reply-layouts.py` interprets each builder forwards over its control-flow
graph, giving every register a symbolic pointer — `sp`, an argument, a
literal-pool constant, a load, a call's return value. Two registers point at
the same object when their roots match, so the buffer is whatever `r1` holds at
the send and a field is any store, or any `strcpy`/`memcpy`/`sprintf`, whose
destination shares that root.

**78 builders, 92 send sites, all 92 resolved. 26 msgTypes** — 18, 20, 21, 22,
24, 51, 59, 60, 61, 62, 101, 103, 109, 111, 112, 147, 150, 151, 152, 153, 154,
504, 600, 801, 999, 9999 — against the 7 this section originally listed. **105 text
fields** that a store-only method cannot see. The map is committed as
`reply-layouts.txt`.

**Every site's msgType is now accounted for**, which took a second pass: 35 are
a constant stored at +0x04, 33 name a non-constant source, and the remaining 23
never write +0x04 at all because the buffer arrives already stamped. For those
the map names the function that stamped it, and the answer is one architecture
repeated four times — a `web_request*` handler allocates or claims the reply
buffer, copies `session` and `msgType` out of the request it is answering,
parks the pointer in a member or a global, and an asynchronous callback later
fills the payload and sends it:

| buffer | sites | stamped by |
|---|---|---|
| `[*0xd2f2e8]` global | 6 Z-Wave/thermostat callbacks | 22 `sltRequestZwave*` handlers, from `[arg r1+0x4]` |
| `[this+0x244]` | 9 zone-list sites | `sltRequestAllZoneCurrStatus`, via `osal_Malloc()` |
| `[this+0x14]` | 6 event-log sites | `sltRequestEventLogUpload`, via `osal_Malloc()` |
| `this+0x18` inline | 2 partition sites | `sltSendPartitionDetailsToWebClient`, `= 21` |

**One shared global reply buffer serves every Z-Wave path.** Two concurrent
Z-Wave requests race on `0xd2f2e8`; a replacement that pipelines requests where
the vendor serialised them can expose that.

What it says:

- **msgType 22 exists and shares a builder with 21.**
  `sltSendChangedPartitionStatus` stores 21 or 22 at `+0x04` on predicated
  paths, and `+0x08` is either `GetOnlineStatus()` or `-1` the same way. It was
  missed by a first count because the map prints `msgType 21 or 22` on one line
  and the regex reading that count took only the first number — the map was
  right and the summary of it was not.
- **The trailing field of a typed frame is uninitialised memory.**
  `sltSendNewPartitionDetails` does `sub sp,sp,#0x250`, `stmib sp,{r2,r3}` —
  session and msgType only — and `sprintf`s the text to `+0x0E`. There is no
  `memset` and `+0x08` is never written, yet Barracuda prints it as the last
  field. The `2` in all 12 captured `0:18:` frames is stale stack that happens
  to be stable. A replacement must pass it through verbatim and must never
  interpret it; `ipc.rs` says so at `frame_typed`.
- **msgType 18 is `sltSendNewPartitionDetails`.** `TRAPS.md` §1 records
  `0:18:` frames arriving 32.98 s apart and mistaken for a button's effect; the
  heartbeat now has a name.
- **msgType 20's payload is at `+0x0E`.** `wsltHandleRawDataFromPanel` builds
  it with `strcpy` then `strcat` from `apl_getEcpConsoleModeData()`. This is
  the console-mode message P10 made real, and it is the one field I said would
  still need the window. It does not.
- **msgType 21's `+0x08` is `GetOnlineStatus()`.** The field `ipc.rs` calls
  `arg` is the panel's online flag on that path; the observed frame
  `0:21:1:fe:…` has `arg=1`, i.e. online. A generic name concealed a specific
  meaning.
- **One msgType is not one layout.** 21 has two builders with different shapes
  (`sltSendChangedPartitionStatus`, `sltSendPartitionDetailsToWebClient`); 101
  has four and 103 has three.
- **`registerclient` (504) writes nothing at `+0x0E`.** Its payload is
  `GetCurrentPartition()` at `+0x90`, a partition description `strcpy`'d to
  `+0x91`, and single bytes at `+0xaf`..`+0xb8` from `GetPanelCalImplementation`,
  `GetArmingModes() & 8`, `GetOperationMode`, `GetTotalPartitions` and
  `isRisSupported`. So `ipc.rs`'s `Reply::parse` is right for the status path it
  came from and wrong for a 504.
- **`sltGoAuthLevelReceived` carries four partition descriptions** at `+0x010`,
  `+0x02f`, `+0x04e`, `+0x06d` — a 31-byte stride — plus the literal texts
  `VALID_USER_CODE`, `INVALID_USER_CODE` and
  `Global ARMING - Not Authorized...!`.

**The method's limits, stated because a short entry is easy to misread.** Only
reachable code is read, so a send with no path from the function entry is
reported as `NOT REACHED`, never dropped. A function with several cases shares
one frame across all of them and stores are pooled per function, so entries
marked `NOTE` may list a field belonging to a different case — the store
address is printed for exactly that check. `<- f(out)` attributes a value to
the first non-library call to receive the pointer, which is right for a scratch
buffer filled once and read after and can mislead for one reused twice. `<- rN`
means the field is real but its producer is not claimed.

**Seven defects were found while building this, and every one had already
produced a confident wrong answer.** They are recorded because the pattern
matters more than the fixes: each looked like a tidy result.

1. Predicated stores (`strbne`, `strbeq`) were skipped by a mnemonic-keyed
   width table, so `registerclient`'s `+0xb0` and `+0xb8` were missing from a
   map that looked finished. Widths now come from capstone's instruction id.
2. A `None`-versus-`int` sort comparison crashed the run partway. The counts
   "45 resolved" and then "15" were both from crashed runs; neither was real.
3. The backward walk that found the buffer register stopped 11 instructions
   back, and `CReceiverThread::run()` sets `r1` at 12 — the fixed-distance
   bound TRAPS §1 warns about, hit again. That plus four other shapes left
   **33 of 78 builders unresolved**.
4. `cmp r0, #0` was treated as *writing* `r0`, destroying the tested value one
   instruction before the predicated store that consumes it.
5. A `pop {r4,r5,pc}` early-return epilogue in the middle of a function
   clobbered registers for the code after it, and `pop {r4,r5,lr}` before a
   tail call did the same.
6. Reading the function linearly fell **through** an unconditional `b` into a
   block only a branch can reach, which reported two buffer pointers as
   `osal_Free()` and `CTimer2::start()`. It also decoded literal pools as
   instructions. Replaced with a worklist over the CFG.
7. `ldrls pc,[pc,r3,lsl #2]` — a gcc jump table — was read as a return, cutting
   every case off: `refreshUploadZoneList` reached 178 of its 768 instructions
   and **two of its send sites disappeared from the map without comment.**
   Decoding the table also required stepping over its own entries, because
   capstone's `disasm()` stops at the first undecodable word rather than
   skipping it (TRAPS §1 again).

8. `stmib sp,{r3,ip}` was dropped whole. Only `STMIA` and `STMDB` were
   handled, so `STMIB` and `STMDA` recorded nothing and `wdelaytimerstart`'s
   entry printed with its session and msgType simply absent. That instruction
   *is* its msgType: **24**.
9. `tuxelf.Elf.v2o` mapped addresses inside sections with `sh_addr == 0`. The
   integer **801** — a literal-pool constant that is a message type — landed in
   `.comment` and read back as `"U) 4.1.2"`, a fragment of the GCC version
   banner, which was published as a field's value. `o2v` has carried a guard
   against exactly this since the phantom-reference bug; `v2o` never did.
10. A literal-pool word was rendered as a pointer whenever a string could be
    read at that address. It is a pointer only if it maps to a loaded section;
    otherwise it is a number, and for msgType it always was.
11. The "who filled this buffer" search reported "no writer found" for an
    inline buffer, because neither branch of the candidate selection matched
    that shape and no search had run. A search that never ran must not report
    an empty result.

Two further errors were caught by the regression diff rather than by the tool:
`osal_MqSend` was being recorded regardless of length, so a **580-byte**
message four instructions away was published as a layout of the reply union;
and `strlen(s)` immediately before `strcpy(dst, s)` was reported as the source
of `dst`.

Guards that now travel with the tool, since all of the above were found by
comparison rather than by inspection:

- `registerclient` is a **positive control** built into `--check`. Its five
  fields were read by hand before the tool existed, so a run that does not
  reproduce them fails loudly. It caught four defects on its first run.
- A send site the linear scan finds but the CFG walk does not reach is
  **reported**, not dropped. That is how the jump-table bug would have been
  caught had it existed then.
- The buffer length is checked from the dataflow at the send *and* by the
  linear scan, so the two methods have to agree.

Two fields the previous tool reported are deliberately **not** in the new map,
both false positives confirmed by reading the code: `setEventIndex +0x000` is a
store to a global (`ldr r3,[pc,#0xb8]; strb r4,[r3]`) on the branch that does
not send, matched only because the old tool compared register *names*; and
`sltSetEventIndex +0x000` is `str r6,[r0,r7]`, a register-indexed store read as
offset 0 because `mem.index` was ignored.

### 5.11 Loose ends recorded, not planned around

- **Which reply msgTypes Barracuda relays versus drops — ANSWERED, and it
  confirms the console-mode finding.** `dispatch_tree.py` gives
  self-inconsistent output on `gettuxedoIPCCommFunc` (overlapping intervals,
  and a handler for msgType 20 that contradicts `TRAPS.md`), so it was not
  used. Instead the reply map's own interpretation was run over Barracuda to
  find every `cmp` whose operand IS the msgType — the word at `sp+0x278`,
  the received buffer being at `sp+0x274`. **The walk was wrong and TRAPS was
  right: 43 constants are compared and 20 is not among them.**

  The comparison is only meaningful because all **92 send sites write the same
  queue**. `0xd2f25c` is the fd, and `CReceiverThread::CReceiverThread` fills
  it from `osal_MqCreate("/Q_ServCmdTrsmtr", …, 0x22c, …)` — checked rather
  than assumed, because `SendChannelDataRefreshtoVideoApp` looks by its name
  like it targets something else and does not.

  | | msgTypes |
  |---|---|
  | **relayed** (sent and compared) | 18, 21, 22, 51, 59, 61, 62, 103, 109, 111, 112, 147, 154, 504, 801, 999, 9999 |
  | **sent but never compared — dropped** | **20**, 24, 60, 101, 150, 151, 152, 153, 600 |
  | compared with no 556-byte builder | 1-9, 19, 25-27, 29, 55, 56, 104, 105, 125, 130, 132, 133, 160-162, 716 |

  The relayed row is what a replacement must handle to be behaviour-compatible.
  The dropped row is what the vendor throws away — msgType 20 is the keypad
  display, which is why console mode is unreachable, and 600 is the doorbell.
  The third row is not dead code by construction: those cases exist for
  senders that are not 556-byte `osal_MqSend` builders, so absence from the
  map is not evidence they are unreachable.

  A `cmp` proves the code distinguishes a value; it does not prove the case
  does anything useful. Read the arm before relying on a type being relayed.

- 13 of 95 `ui_sendMsgToUi` call sites did not resolve to a literal mtype, so the
  mtype→emitter map is 82/95, not complete. Intra-tuxedo; does not affect us.
- `/mqUI_Input_Queue` has a **second writer**: `initNetLinkStatusMonitor`
  @`0x33478` creates it into a separate global @`0xd0ebcc` and
  `apl_SendNetLinkStatusEventToUi` @`0x32bf0` sends **4-byte** messages on it.
  **READ**, and it explains why `tuxedo` holds that queue on two fds. So the
  0xD0-byte struct is not the queue's only message shape. Intra-tuxedo; recorded
  because the mapping's "only writer" claim was refuted and the correction should
  not be lost.
- Whether `/TotalConnect` and a replacement writing `/Q_ServCmdRcver` concurrently
  ever collide in practice, and whether `/tuxedo` distinguishes them. Both write
  at priority 1 with no sender identifier beyond `sessionId`. Watch for it during
  stage 7.
- ~~Whether `supervis` acts against a process that stops writing
  `/g_mqSupervisionThreadIn`. Not decoded.~~ **ANSWERED: it does not, so a
  stage-6 cutover binary needs no heartbeat.** There is no per-app last-seen
  timestamp for silence to be measured against — `time()` is reached from
  exactly four places, all of them IPC deadlines and log timestamps — and
  `SupervisTimeout` decides on `getProcessPid`, file descriptors, pipes and
  memory, never reading the queue at all. §1.7 B8 argued the same conclusion
  from Barracuda's single `sigHandler` caller; this replaces that inference
  with the mechanism.

  A third strand: **the one thread `main` creates is not a monitor.** On stock
  it is `serverThreadForCamera` at `0xc5e8`, and it calls only
  socket/bind/listen/accept/fcntl/setsockopt/close/puts/pthread_exit — no
  queue, no kill, no clock. On the live v13 there is **no thread at all**: P9
  replaces the `bl pthread_create` there with `mov r0,#1`.

  **THE CONCLUSION IS NOT P9-CONTINGENT, and that was worth establishing rather
  than assuming.** An earlier draft said "creates exactly one thread", which is
  the stock binary's incidental shape written down as the requirement and reads
  as false against the panel in service; the opposite error would be to treat
  P9 as the reason the answer holds, which would leave a cutover binary running
  before P9, without it, or on a panel where it did not take, uncovered. Both
  are wrong. The property is *nothing that could notice silence*, and it holds
  twice over:

      stock v12    thread present, and harmless   -> no monitoring
      live v13     thread absent (P9)             -> no monitoring

  P9 also does not divert `main`. It forces the "thread creation failed" branch,
  and both branches converge at `0xc4f0` — the failure path costs one `puts()`
  and skips one flag store. The queue read, `SupervisTimeout` and `time()` are
  all downstream of that convergence and untouched. So "the P9 bytes are nowhere
  near this path" is true of the supervision decision path and of `main`'s
  control flow; it was only wrong as a statement about the thread site itself.

  **RE-DERIVED HERE, not taken on report.** `probe/supervis_heartbeat.py
  <rootfs>/supervis` takes the vendor binary from the operator the way
  `ci/test_hdr.py` takes `TUXEDO_FW_DIR`, since the binaries are deliberately
  absent from this repo. Run from this repo's own copy against three binaries on
  the build VM:

  **Three exit states, and the third one matters.** "Could not evaluate" is not
  "the claim is false" — handing the checker the wrong binary must not read as a
  refutation any more than it may read as a pass:

      rc=0   evaluated, the claim holds
      rc=1   evaluated, the claim is FALSE
      rc=2   could not evaluate: not supervis, not an ELF, no such path

  | binary | exit | result |
  |---|---|---|
  | stock `supervis` | 0 | 7 assertions hold, thread present and harmless |
  | live v13 `supervis` | 0 | 6 hold, "no thread at all (P9 removes it)" |
  | **synthetic control** | **1** | **exactly 2 FAIL**, the other 5 still pass |
  | `Barracuda`, `tuxedo` | 2 | "has no `SupervisTimeout` — this is not supervis" |
  | not an ELF, missing path | 2 | refused, nothing checked |

  **THE CONTROL HAD TO BE BUILT, and the reason is a trap in itself.** Barracuda
  was the original control — it failed three assertions, which was the only
  evidence the checker could discriminate at all. Correctly reclassifying it to
  `rc=2` was right *and it silently deleted the only failing case*, leaving a
  checker that had never been observed to fail anything. **A tightening that is
  correct can destroy your negative control; check afterwards that you can still
  make it go red.**

  So `probe/mkcontrol.py` builds one: it copies stock `supervis` and redirects
  one `bl` inside `SupervisTimeout` to `osal_MqRecv`, producing a binary where
  the 600 s housekeeping genuinely does read the supervision queue. The checker
  then fails **exactly the two assertions that should fail** — "queue read only
  by main" and "SupervisTimeout never reads the queue" — while the other five
  still pass. Targeted rather than blanket is what separates a control from a
  broken checker. It writes a copy and leaves the original untouched, verified
  by hash.

  Found by the firmware session, which could not commit it while this repository
  was held for the publication rewrite. Re-confirm before stage 6 is booked if
  anything else about `supervis` turns out to be wrong.
- Long-run stability. The longest any test binary had run on this panel was ~50
  seconds. No soak, no memory-growth-over-hours measurement, no concurrency
  beyond a handful of connections, all on a single-core box. Every RSS figure in
  the runtime survey is early-life. Stage 3 should run for a week before stage 6
  is booked.

  **Started 2026-09-06.** The stage-3 shim is running on `:8443` with TLS, and
  `emu/soak-sampler.sh` appends a row every 5 minutes to `/tmp/soak.tsv`:
  shim RSS, fd count, thread count, whether `:8443` is still listening,
  Barracuda's RSS and system `MemFree`. Started early on purpose — it costs a
  week of wall-clock and nothing else, so starting it late is the thing that
  would delay stage 6.

  Baseline row, first sample:

  ```
  pid 3027  rss 544 kB  fds 6  threads 2  :8443 up  barracuda 7148 kB  memfree 67332 kB
  ```

  544 kB against the ~31 MB `BARRACUDA_MEMORY` ceiling (§5.2). What the week has
  to show is that this number does not climb and the fd count does not drift;
  those are the two failure modes a 50-second test cannot see. Read it with
  `ssh root@panel 'cat /tmp/soak.tsv'`.

  The sampler finds the shim by its `exe` symlink rather than its cmdline,
  because the cmdline carries the token and matching on it is how a `pkill` once
  killed its own ssh session (`TRAPS.md` §4). Note `/tmp` is tmpfs: a panel
  reboot loses the log, which is acceptable — a reboot voids the soak anyway,
  and losing the log is how we would find out.

  **At 11.8 h (142 samples):** pid unchanged, listener up in 142 of 142, fds
  flat at 6, RSS 544 -> 764 kB (+1.9 kB/h, which puts the 31 MB ceiling 670
  days out), Barracuda flat at ~12.4 MB.

  `MemFree` fell 67332 -> 57528 kB over the same period, which reads like a
  leak and is not one: `Cached` is 28120 kB against `Buffers` 8 kB and `Slab`
  4284 kB, so the decline is reclaimable page cache. **The sampler does not
  record `Cached`, so its `MemFree` column cannot be read on its own** -- check
  `/proc/meminfo` before treating a fall as growth. The column is deliberately
  not being added mid-run: the report parses by position and this is a running
  measurement.