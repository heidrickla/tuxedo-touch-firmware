# What the TLS work does and does not protect

Written alongside `tuxedo-ca.py` and `tuxedo-tls-push.py` specifically so nobody
reads "modern TLS 1.3 on the panel" as "the panel is secured". It is not. TLS
fixes one problem — traffic on the wire and server identity — and the panel has
several that TLS cannot touch.

Everything below is measured on this unit unless labelled otherwise.

## What it does fix, and it is worth having

**The shipped certificate is worthless and the replacement is not.** The vendor
cert is expired, and its private key is compiled into the `Barracuda` binary:
`SharkSsl_constructor` is called twice, both inside `openSocketCon`, both with
that cert; there is no `setCertificate` API in the build; `sharkssl_PEM_to_RSAKey`
has zero callers; and no `.pem`/`.crt`/`.key` exists anywhere in the rootfs.
**Anyone who downloads the firmware has the panel's private key.**

So before this work, a LAN attacker could impersonate the panel or decrypt its
sessions with a key anyone can extract. After it, the key exists only on the
owner's workstation, the leaf is verifiable against a CA the owner controls, and
the negotiated session is TLS 1.3 with AES-256-GCM. That is a real improvement
and it is the whole of the improvement.

## What it does not fix

### 1. Everything runs as root, so file modes buy very little

`server.key` is `0600` in a `0700` directory. On a single-uid box **this is not a
defence against local code execution.** Any code running on the panel is already
root and can read the key.

What the modes genuinely buy, stated without inflation:

- the key stays out of a `tar` of the config partition shared for support
- an accidental serve-the-config-directory bug becomes non-fatal

That is it. Claiming more would be overselling.

### 2. Physical access is total

The unit is a wall-mounted keypad. Anyone who can unscrew it can pull the SD
card, read the config partition, and take `server.key`. The primary bootloader
mounts FAT off SD and loads a `BOO`-tagged secondary bootloader, so physical
access is also code execution.

Generating keys on the workstation limits the blast radius — the CA key is never
on the panel, so a stolen panel key lets an attacker impersonate *that panel*
until it is rotated, not mint new certificates. Rotation is `issue` + `push`,
which is the reason the owner-CA model was chosen over a self-signed leaf.

### 3. The push stream needs no credential at all

**MEASURED:** `GET /SimpleDebugger.interface/G.` returns live alarm state —
armed/disarmed, the exit-delay countdown ticking down, partition status — with
**no cookie, no login, and no prior registration**, on port 80 *and* port 6280.
`G.` auto-registers the client.

For anyone deciding whether a house is empty, that is the single most useful
signal in it, and today it is readable by anything on the LAN. TLS does not
change this: the plaintext port is still there, and the stream does not
authenticate on any port.

Baseline measured 2026-09-06 with `test-stream-auth.py`, which quantifies it
rather than asserting it. All **four** listeners were exercised, not two — the
harness previously only covered the plaintext pair, which would have hidden a
split result between them:

```
anonymous port 80        EXPOSED   9 frames, 4 carrying alarm state
anonymous port 6280      EXPOSED  17 frames, 8 carrying alarm state
anonymous port 443  tls  EXPOSED   9 frames, 4 carrying alarm state
anonymous port 9443 tls  EXPOSED  17 frames, 8 carrying alarm state
authenticated  x4        OK        frames on every listener
panel web UI             OK        HTTP 200
```

The replacement is designed to require the session cookie on this path, and the
consumer (`ha-tuxedo-touch`) already sends one, so closing it costs nothing.

**One fix covers all four ports.** `HttpServer_constructor` has exactly one
caller, and `initAndInstallServlet` is handed the same server object every other
directory insertion in `installVirtualDir` uses — so ports 80, 443, 6280 and 9443
are four listeners (`HttpServCon` x2, `HttpSharkSslServCon` x2, all built in
`openSocketCon`) sharing **one** `HttpServer` and therefore one directory tree.
There is likewise only one EhDir object, at `0x55b59c`. So authenticating the
push stream is a single change at the directory, not a per-port exercise, and a
fix that appeared to work on port 80 alone would be a sign something was wrong.

**Status 2026-09-06: the fix is built and verified, and not yet flashed.** P13
(`PUSH-STREAM-AUTH.md`) gates the endpoint on the session. Run under `qemu-user`
against the real ARM binary with the panel's own configuration, it returns
`HTTP/1.1 401` to an anonymous client on all four listeners while an
authenticated client still receives frames, with `/` and `/home.html` unchanged
and no fault in the request path. The live-panel baseline it has to beat was
measured the same day and is the table above.

**Until it is flashed, this is still open on the panel.**

### 4. The camera scan broadcasts the LAN inventory

Observed on that same stream: `0:55:` frames enumerating discovered devices —
hostnames, IPs, across multiple subnets (printers, a receiver, and so on). Same
exposure as above and the same fix.

### 5. TLS is mandatory on the REST path but login is not

**MEASURED:** every `/system_http_api/` request over plain HTTP answers
`302 -> https://<host>:443/...`, so the API cannot be driven in the clear. But
**login succeeds over plain HTTP.** That asymmetry is dangerous in a specific
way: a client misconfigured to plain HTTP authenticates successfully, then
silently fails every command, because the session is real and the API redirect is
not followed. It looks like a working integration that cannot arm.

### 6. Failed logins: FIXED on this panel by P1, still present on stock

**Corrected 2026-09-06.** An earlier version of this section said three failed
logins permanently disable every web account on this unit. That describes
**stock** firmware. This panel runs P1, which removes it.

Stock `updateLoginFailureCount` does two things on the third failure:

```
cmp r0, #3
bne  0x155fc                     ; not the 3rd -> skip ahead
       json_new_i("accountLocked", 1)
0x155fc  <- P1 site; stock FALLS THROUGH into:
       json_new_i("status", 0)   ; the permanent disable
0x15624  cmp r5, #5
```

`status` is read by `readUserNamePasswordFromJSON` — the login path — so
`status = 0` is what actually disables the account, and it survives a reflash.

**P1 replaces the fall-through at `0x155fc` with `b 0x15624`**, which skips the
`status = 0` write on *both* branches. So on a patched panel accounts are never
permanently disabled. `accountLocked = 1` is still written on the third failure,
but it is cleared by `resetLoginFailureCount` — the in-memory path that expires
after 300 s — and the login gate reads `status`, not `accountLocked`.

**What remains, and it is much smaller:** five failures still trip the in-memory
lockout for 300 s. That is a temporary denial of service against the web
interface by an unauthenticated LAN client, not a permanent lockout, and it
clears itself. Worth bounding by source address eventually; not urgent.

**On stock firmware the original claim stands in full**, which matters for anyone
reading this repo who has not applied P1.

Tooling in this repository still must not submit a deliberately wrong password —
the conformance suite excludes that path by construction rather than by
discipline — because the repo targets stock panels too, and because a 300 s
self-inflicted outage during a test is pointless.

### 7. `supervis` has a root-command primitive on a message queue

Message ID 21 on `/g_mqSupervisionThreadIn` reaches a root command execution
path. It is **not** reachable from its TCP socket, and nothing here relies on it
— recorded so the threat model is honest rather than because it is exploitable
remotely today. Single-source finding, not independently replicated.

### 8. A crash-looping web server reboots the panel

`supervis` is the sole `/dev/watchdog` kicker and disarms the keepalive after 24
relaunches. So a replacement that fails to start does not fail quietly — it
resets the unit. This is a robustness constraint on the replacement, not an
attack, but it is the failure mode most likely to be hit by accident.

## The honest summary

After this work the panel has **a real certificate and a modern TLS stack**. It
still has an unauthenticated live-alarm-state feed and no meaningful separation
between processes. The permanent account lockout is **already fixed here by P1**
and is a live issue only on stock firmware.

TLS was worth doing because the alternative was a published private key. It is
the first item on a list, not the end of one. The unauthenticated stream (§3) is
the highest-value remaining fix and it is already designed; it ships with the
Barracuda replacement.

Priority order, if the list is ever worked:

1. §3 authenticate the push stream — costs the known consumer nothing
2. §6 bound the remaining 300 s in-memory lockout by source address — the
   permanent on-disk one is already fixed by P1
3. §5 refuse plaintext login, so a misconfigured client fails loudly at the door
4. §4 falls out of §3
