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

Dispatch completeness, **corrected**: the mapping pass said 62 command codes;
the review's independent simulator says **82**, and the mapping's own
enumeration expands to 81 (it omits 102). The set is
`1-19, 25-27, 29, 52-58, 100, 102, 104-129, 147, 154, 300-303, 500-503, 508,
509, 601-608, 700, 800, 801, 888`. Not every one has a slot: 102, 123 and 124
branch straight back to the receive loop and print nothing; 100 and 116 only
`puts()`. Use 82 and the corrected set.

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
- **Unknown, and it must be checked before stage 6:** whether `/tuxedo` itself
  reads `webuseraccountsenc.json`. §5.6.

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

Per `CONTRIBUTING.md`: anything that must work at boot gets executed under
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
   |   CReceiverThread::run  ->  82 command codes              |
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
   extracted rootfs first, `/dev` as shipped (`CONTRIBUTING.md`).

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
2. *The 404-byte command encoder.* **Started 2026-09-06 — the outbound
   structure is recovered.** See below.

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
writes **500** into `+0x04`, and 500 appears nowhere in the dispatch table above
— `/tuxedo` contains **no `cmp <reg>, #500` at all**. It is not dispatched like
the other commands.

But §B7's `registerclient` is real and is in **`/tuxedo`**, at `0x13c2f8`, and
reading it explains the whole exchange:

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

`CReceiverThread::unregisterclient` @`0x13c00c` *is* called from
`CReceiverThread::run`. How `registerclient` is reached, given no `cmp #500`,
is not yet established — a Qt signal/slot connection is the obvious candidate
and has not been checked.

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

### Stage 6 — The IPC cutover, read-only, bounded window

**This is the irreversible-feeling one. It is the only stage requiring a booked
window and Lewis at the panel.**

**Change:** `tuxweb` stops exec'ing the vendor and instead opens the two queues.
It **receives** on `/Q_ServCmdTrsmtr` and **sends nothing**. It logs every 556-byte
reply raw, and serves the legacy shim from them.

Mandatory safety features, all in the binary before this stage runs:

- **Deadman exec.** A timer armed at startup, default 15 minutes, resettable by
  an authenticated call. On expiry the binary closes its sockets and queues and
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
`msgType` values match the 43-entry map; the legacy shim emits frames matching the
stage-0 corpus; HA's alarm state tracks the touchscreen. It also gives us the raw
payloads for the 36 msgTypes that were never decoded past `+0x0E`.

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

### 5.2 `supervis`'s poll period, and the size of the stage-6 window

`SupervisTimeout` re-arms with `ArmSWTimer(timer, 0x258, 0, 0, 0)`. Whether
`0x258` (600) is milliseconds or seconds is a 1000x difference: a 0.6 s poll or a
10 minute one. It sets how much slack stage 6 has before the relaunch counter
starts climbing, and therefore how conservative the deadman timer must be.

**Cheapest experiment:** free. Read `CreateSWTimer`/`ArmSWTimer` in `supervis`
statically and determine the units. Also read `SuperViseMemoryUsage` /
`BARRACUDA_MEMORY` for the memory ceiling while in there — a ~1 MB Rust process
is almost certainly far under it, but "almost certainly" is not a number.

### 5.3 Does killing Barracuda risk the hardware watchdog?

Both `supervis` and Barracuda hold fd 4 on `/dev/watchdog`; the standard Linux
driver refuses a second open, so inheritance is the likely explanation but was
not confirmed. **INFERRED.** If Barracuda's exit somehow released the watchdog,
the stage-6 window would end in a reset. It should not — closing one duplicate of
an open file description does not close the other — but "should not" is doing
work here.

**Cheapest experiment:** free, static. Confirm `wdg_init` opens `/dev/watchdog`
once at `supervis` startup and never closes it, and that no `Barracuda` symbol
mentions the watchdog (already **MEASURED**: zero watchdog/wdg symbols in
Barracuda). Unresolved side note kept for the record: the extracted `config.gz`
says `# CONFIG_WATCHDOG is not set` yet `/dev/watchdog` exists and is kicked. The
config is probably stale or mismatched; it was not reconciled.

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

### 5.5 Does busybox `seedrng` credit entropy on 2.6.31?

Decides whether on-device key generation is ever recommendable, or whether
workstation generation is the only supported path. If `seedrng`'s implementation
calls `getrandom()`, it fails outright here.

**Cheapest experiment:** stage 2, seed dir under `/tmp`, watch `entropy_avail`
across the call. Minutes. Note it mutates the kernel pool, which is why it needs
its own stage rather than being folded into a read-only sweep.

### 5.6 Does `/tuxedo` read `webuseraccountsenc.json`?

§1.6 has v1 abandoning the vendor's web-account store. If `/tuxedo` reads it, the
consequences of stopping maintenance are unknown.

**Cheapest experiment:** free. `e.grep()` for the string in the `tuxedo` binary
and check for a genuine data reference, not a symtab hit. Minutes.

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

**Cheapest experiment:** free. Read `TuxedoDetails.json` on the panel for a peer
entry. A single-panel installation never exercises the path. If there is a peer,
the follow-up is to check what the libcurl call sets for `CURLOPT_SSL_VERIFY*`.

### 5.8 Client acceptance of a private root for an IP-literal SAN

Decides whether the documentation should push owners toward a hostname plus local
DNS rather than the bare `203.0.113.5` they use today, and whether a self-signed
leaf with `CA:FALSE` in the trust store would have been enough (§3.4).

**Cheapest experiment:** issue a leaf with an IP SAN from a throwaway CA, install
the root, open current Chrome and Firefox. An hour, off-panel, no panel risk.

### 5.9 Can Home Assistant set an Authorization header on a long-lived multipart stream?

Decides whether the query-parameter token form is optional or mandatory.

**Cheapest experiment:** read `ha-tuxedo-touch`'s stream client. Free.

### 5.10 The reply payload beyond `+0x0E`

Mapped for msgTypes 1, 18, 19, 20, 21, 22 and 504. The other 36 dispatched types
(Z-Wave, camera, event log, thermostat) are not decoded. This is not a blocker
for v1 — security and status are covered — but it bounds how much of the feature
set can be rebuilt later.

**Cheapest experiment:** it falls out of stage 6 for free. The read-only window
logs every reply raw; correlating them against touchscreen actions decodes them
without any additional risk. Plan for a longer capture during that window than the
minimum the stage needs.

### 5.11 Loose ends recorded, not planned around

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
- Whether `supervis` acts against a process that stops writing
  `/g_mqSupervisionThreadIn`. Not decoded. §1.7 B8 argues we do not need to
  heartbeat, from Barracuda's single `sigHandler` caller; if stage 5 shows
  otherwise, adding a heartbeat is trivial.
- Long-run stability. The longest any test binary has run on this panel is ~50
  seconds. No soak, no memory-growth-over-hours measurement, no concurrency
  beyond a handful of connections, all on a single-core box. Every RSS figure in
  the runtime survey is early-life. Stage 3 should run for a week before stage 6
  is booked.