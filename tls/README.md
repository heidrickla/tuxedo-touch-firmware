# TLS for the Tuxedo Touch

The panel ships an **expired certificate whose private key is compiled into the
`Barracuda` binary**. There is no `setCertificate` API in the build, the PEM
loader (`sharkssl_PEM_to_RSAKey`) has zero callers, and no `.pem`/`.crt`/`.key`
exists anywhere in the rootfs. So the shipped TLS authenticates nothing: anyone
who extracts the binary has the key.

This directory is the replacement path. **No key material is in this repository
and none ever will be** — `ci/checks.sh` fails the build if any appears.

## Status

| | |
|---|---|
| `tuxedo-ca.py` | **working**, verified end to end |
| everything else | not built yet |

`tuxedo-ca.py` is verified rather than assumed: a generated leaf was served over
a real TLS handshake and accepted by a client trusting only the owner CA —
**TLS 1.3, `TLS_AES_256_GCM_SHA384`, IP SAN matched** — and a negative control
without the CA correctly rejected it.

## Why keys are generated on the workstation

The panel cannot be trusted to make one. **MEASURED on the unit:**

- `entropy_avail` sits at an equilibrium of roughly **130-185 bits and does not
  accumulate**. Sampled over 100 s it went `173 173 173 184 184 184 131 131 131
  142 142` — net **-31 bits**. Waiting does not help.
- No `/dev/hwrng`; `lsmod` empty; `dmesg` shows only `alg: No test for stdrng`.
- No random-seed save or restore anywhere in `/etc/rc.d/`.
- `getrandom()` is ARM syscall **384**, above this kernel's 363 ceiling, so
  there is **no wait-until-seeded primitive at all**.

A weak key is worse than an expired one: expiry is visible and weakness is not.
On-device generation may be supported later as an explicitly gated fallback,
never as a silent default.

## Trust model

Four options were considered. **An owner-run CA is the default.**

| | model | verdict |
|---|---|---|
| a | self-signed leaf | fine for one or two clients; no rotation story |
| b | owner-supplied cert dropped in the config partition | **not a fourth model — it is the interface.** Every other option ends in writing `server.key` + `server.crt` and reloading |
| c | **small owner-run CA on the workstation** | **default** |
| d | ACME / DNS-01 | supported, run off-panel, with a Certificate Transparency warning |

Why (c): it is the only option with a clean rotation story — the leaf changes
every renewal and no client trust store is touched. It works offline with no
domain and no DNS provider, which matters because **the thing being secured is
an alarm panel that must keep working when the internet is down**. And the
long-lived secret stays on a workstation rather than on a device in a hallway
that anyone can unscrew.

## Use

```bash
python tls/tuxedo-ca.py init-ca --dir ~/.tuxedo-ca      # once
python tls/tuxedo-ca.py issue   --dir ~/.tuxedo-ca --ip 203.0.113.5
python tls/tuxedo-ca.py show    --dir ~/.tuxedo-ca      # what is issued, what expires when
```

Then install `~/.tuxedo-ca/ca.crt` as a trusted root on the machines that talk to
the panel. **`ca.key` never leaves that directory and never goes on the panel** —
only the leaf does.

Leaves are EC P-256, 397 days (the CA/Browser Forum maximum, which keeps renewal
a habit rather than an emergency). The panel has no DNS name, so the SAN is an
**IP literal** — a CN alone has not been honoured by anything for years.

## What `0600` on the panel does and does not buy

The design puts the key at `/opt/tuxedo/configuration/tls/server.key` mode
`0600`, in a `0700` directory. Stated honestly: **everything on the panel runs as
root, so this is not a defence against local code execution.** Its value is
narrower and real:

- it keeps the key out of a `tar` of the config partition shared for support
- it makes an accidental serve-the-config-directory bug non-fatal

The parent directory is `drwxr-xr-x` and most of its entries are `0644`, so
`tls/` must **assert** its mode and the installer must **verify** it, never
inherit it.

`/opt/tuxedo/configuration` is `/dev/mtdblock17` — jffs2, rw, 59 MB with 57 MB
free, and it **survives a reflash**, which is what makes it the right home.

## Still to build

`tuxedo-tls` (on-panel), `tuxedo-tls-push.py` (push, then verify by reconnecting
and asserting the served certificate matches what was pushed), the ACME hook, the
recovery path, and `THREAT-MODEL.md`. See §3 of `WEBSERVER-REPLACEMENT.md`.
