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

The replacement is designed to require the session cookie on this path, and the
consumer (`ha-tuxedo-touch`) already sends one, so closing it costs nothing.
**Until the replacement ships, this is open.**

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

### 6. Three failed web logins disable every web account, permanently

The on-disk failure count survives a reflash. There is a self-clearing in-memory
lockout (5 attempts, 300 s — `resetLoginFailureCount`, reached through the
LoginTracker `Validate` vtable thunk), but the on-disk `WEBUSERS status=0` path
shows no expiry. **A LAN attacker can therefore lock the owner out of the web
interface with three requests and no credentials.** TLS does not help; the
requests are well-formed.

This is why no tooling in this repository may submit a deliberately wrong
password, and why the conformance suite excludes that path by construction
rather than by discipline.

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
still has an unauthenticated live-alarm-state feed, a trivially triggered
permanent account lockout, and no meaningful separation between processes.

TLS was worth doing because the alternative was a published private key. It is
the first item on a list, not the end of one. The unauthenticated stream (§3) is
the highest-value remaining fix and it is already designed; it ships with the
Barracuda replacement.

Priority order, if the list is ever worked:

1. §3 authenticate the push stream — costs the known consumer nothing
2. §6 make the on-disk lockout expire, or bound it by source address
3. §5 refuse plaintext login, so a misconfigured client fails loudly at the door
4. §4 falls out of §3
