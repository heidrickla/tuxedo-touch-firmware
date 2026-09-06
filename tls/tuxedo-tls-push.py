#!/usr/bin/env python3
"""Install a leaf certificate on the panel, then prove it is the one being served.

    python tls/tuxedo-tls-push.py --leaf ~/.tuxedo-ca/issued/203.0.113.5
    python tls/tuxedo-tls-push.py --leaf ... --verify-port 8443
    python tls/tuxedo-tls-push.py --leaf ... --rollback

The last step is the point. A copy that reports success proves the bytes left
this machine, not that the panel is serving them -- `deploy.py` once reported
success having written nothing at all. So after installing, this reconnects over
TLS and asserts the SHA-256 of the served certificate equals the SHA-256 of the
leaf it just pushed. Anything less is a copy, not an installation.

Destination is `/opt/tuxedo/configuration/tls/`, which is `/dev/mtdblock17` and
SURVIVES A REFLASH -- unlike the rootfs, where anything written over SSH is lost
the next time an image is flashed.

Modes are asserted, never inherited: the parent directory is `drwxr-xr-x` and
most of its entries are `0644`.
"""

import argparse
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys

REMOTE_DIR = "/opt/tuxedo/configuration/tls"
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15",
            "-o", "LogLevel=ERROR"]


def ssh(host, key, cmd, data=None, check=True):
    """Run a command on the panel. The command is an ssh ARGUMENT and any bytes
    go on stdin -- they cannot share stdin, which has bitten this project."""
    argv = ["ssh"] + (["-n"] if data is None else []) + \
           ["-i", key] + SSH_OPTS + [f"root@{host}", cmd]
    p = subprocess.run(argv, input=data, capture_output=True)
    if check and p.returncode != 0:
        sys.exit(f"ssh failed ({p.returncode}): {p.stderr.decode(errors='replace').strip()}")
    return p.stdout.decode(errors="replace").strip()


def sha256_of_pem_leaf(path):
    """SHA-256 over the DER of the FIRST certificate in a PEM file."""
    import base64
    body, inside = [], False
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if "BEGIN CERTIFICATE" in line:
                inside = True
                continue
            if "END CERTIFICATE" in line:
                break
            if inside:
                body.append(line.strip())
    if not body:
        sys.exit(f"{path}: no certificate found")
    return hashlib.sha256(base64.b64decode("".join(body))).hexdigest()


def served_fingerprint(host, port, timeout=20):
    """SHA-256 of the certificate the panel actually presents. Deliberately does
    NOT verify the chain: we are identifying what is served, not trusting it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
            return hashlib.sha256(der).hexdigest(), t.version()


def install(args):
    leaf = args.leaf
    key_p = os.path.join(leaf, "server.key")
    crt_p = os.path.join(leaf, "chain.pem")
    meta_p = os.path.join(leaf, "meta.json")
    for p in (key_p, crt_p):
        if not os.path.exists(p):
            sys.exit(f"missing {p}; run tuxedo-ca.py issue first")

    want = sha256_of_pem_leaf(os.path.join(leaf, "server.crt"))
    print(f"leaf sha256   {want}")

    # Keep exactly one previous generation, as the design specifies.
    ssh(args.host, args.key,
        f"set -e; mkdir -p {REMOTE_DIR}; chmod 700 {REMOTE_DIR}; "
        f"if [ -f {REMOTE_DIR}/server.key ]; then "
        f"  rm -rf {REMOTE_DIR}/rollback; mkdir -p {REMOTE_DIR}/rollback; "
        f"  chmod 700 {REMOTE_DIR}/rollback; "
        f"  cp -p {REMOTE_DIR}/server.key {REMOTE_DIR}/chain.pem "
        f"     {REMOTE_DIR}/meta.json {REMOTE_DIR}/rollback/ 2>/dev/null || true; "
        f"fi")
    print(f"rollback      previous generation kept in {REMOTE_DIR}/rollback")

    for local, remote, mode in ((key_p, "server.key", "600"),
                                (crt_p, "chain.pem", "644")):
        with open(local, "rb") as fh:
            blob = fh.read()
        ssh(args.host, args.key,
            f"set -e; cat > {REMOTE_DIR}/{remote}.new && "
            f"chmod {mode} {REMOTE_DIR}/{remote}.new && "
            f"mv {REMOTE_DIR}/{remote}.new {REMOTE_DIR}/{remote} && sync",
            data=blob)
    if os.path.exists(meta_p):
        with open(meta_p, "rb") as fh:
            ssh(args.host, args.key,
                f"cat > {REMOTE_DIR}/meta.json && chmod 644 {REMOTE_DIR}/meta.json",
                data=fh.read())

    # Assert the modes actually took rather than assuming.
    listing = ssh(args.host, args.key,
                  f"PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH; "
                  f"ls -l {REMOTE_DIR} | grep -E 'server.key|chain.pem'; "
                  f"ls -ld {REMOTE_DIR}")
    print("installed:")
    for line in listing.splitlines():
        print("   ", line)
    bad = []
    for line in listing.splitlines():
        if "server.key" in line and not line.startswith("-rw-------"):
            bad.append("server.key is not 0600")
        if "chain.pem" in line and not line.startswith("-rw-r--r--"):
            bad.append("chain.pem is not 0644")
        if line.rstrip().endswith(REMOTE_DIR) and not line.startswith("drwx------"):
            bad.append(f"{REMOTE_DIR} is not 0700")
    if bad:
        sys.exit("  MODE CHECK FAILED: " + "; ".join(bad))
    print("  modes verified")
    return want


def verify(args, want):
    port = args.verify_port
    print(f"\nverifying what the panel actually serves on :{port}")
    try:
        got, ver = served_fingerprint(args.host, port)
    except Exception as e:
        print(f"  could not connect: {type(e).__name__}: {e}")
        print("  Install is complete but UNVERIFIED. Start the TLS server and")
        print("  re-run with --verify-only, or treat this as a copy, not an install.")
        return 1
    print(f"  served sha256 {got}")
    print(f"  TLS version   {ver}")
    if got == want:
        print("\n  VERIFIED: the panel is serving the certificate that was pushed")
        return 0
    print("\n  MISMATCH: the panel is serving a DIFFERENT certificate.")
    print("  The old one is probably still loaded -- restart the TLS server.")
    return 1


def rollback(args):
    # Check separately from the restore. Folding them together made a missing
    # rollback generation surface as a bare "ssh failed (1):" with no message,
    # because the remote script's own explanation never reached the user.
    present = ssh(args.host, args.key,
                  f"[ -f {REMOTE_DIR}/rollback/server.key ] && echo yes || echo no",
                  check=False)
    if present != "yes":
        print(f"No previous generation to roll back to "
              f"({REMOTE_DIR}/rollback/server.key does not exist).")
        print("A rollback copy is only made when a certificate is REPLACED, so")
        print("there is nothing to restore after a first install.")
        return 1
    ssh(args.host, args.key,
        f"set -e; cd {REMOTE_DIR}; "
        f"cp -p rollback/server.key server.key && chmod 600 server.key; "
        f"cp -p rollback/chain.pem chain.pem && chmod 644 chain.pem; "
        f"cp -p rollback/meta.json meta.json 2>/dev/null || true; sync")
    print("Restored the previous certificate generation.")
    print("Restart the TLS server for it to take effect, then re-run with")
    print("--verify-only to confirm which certificate is actually being served.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="203.0.113.5")
    ap.add_argument("--key", default=os.path.join(os.path.expanduser("~"),
                                                  ".ssh", "tuxedo_ed25519"))
    ap.add_argument("--leaf", help="an issued/ directory from tuxedo-ca.py")
    ap.add_argument("--verify-port", type=int, default=443)
    ap.add_argument("--verify-only", action="store_true",
                    help="do not install; just report what is being served")
    ap.add_argument("--rollback", action="store_true")
    args = ap.parse_args()

    if args.rollback:
        return rollback(args)
    if args.verify_only:
        if not args.leaf:
            got, ver = served_fingerprint(args.host, args.verify_port)
            print(f"served sha256 {got}\nTLS version   {ver}")
            return 0
        return verify(args, sha256_of_pem_leaf(os.path.join(args.leaf, "server.crt")))
    if not args.leaf:
        sys.exit("--leaf is required (or use --verify-only / --rollback)")
    return verify(args, install(args))


if __name__ == "__main__":
    sys.exit(main())
