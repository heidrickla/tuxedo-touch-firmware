#!/usr/bin/env python3
"""Owner-run CA for the Tuxedo Touch. Runs on the WORKSTATION, never the panel.

    python tls/tuxedo-ca.py init-ca   --dir ~/.tuxedo-ca
    python tls/tuxedo-ca.py issue     --dir ~/.tuxedo-ca --ip 203.0.113.5
    python tls/tuxedo-ca.py show      --dir ~/.tuxedo-ca

Why the workstation. The panel cannot be trusted to generate a key: its
`entropy_avail` sits at an equilibrium of roughly 130-185 bits and does not
accumulate, there is no hardware RNG, and `getrandom()` is syscall 384 which
does not exist on this 2.6.31 kernel, so there is no wait-until-seeded
primitive. A weak key is worse than an expired one, because expiry is visible
and weakness is not.

Why an owner-run CA rather than a self-signed leaf. It is the only option with a
clean rotation story: the leaf changes at every renewal and no client trust store
is touched. It needs no domain and no DNS provider, which matters specifically
because the thing being secured is an alarm panel that must keep working when the
internet is down. And the long-lived secret stays on a workstation rather than on
a device in a hallway that anyone can unscrew.

NOTHING THIS WRITES BELONGS IN THE REPOSITORY. The default directory is outside
the tree for that reason, and `ci/checks.sh` rejects key material besides.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit("needs 'cryptography': python -m pip install cryptography")

CA_DAYS = 3650
LEAF_DAYS = 397          # CA/Browser Forum maximum; keeps renewal a habit


def _secure_dir(path):
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass          # Windows; the check below reports it rather than pretending


def _write(path, data, mode):
    """Write, then assert the mode actually took."""
    with open(path, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(path, mode)
        got = stat.S_IMODE(os.stat(path).st_mode)
        if got != mode and os.name != "nt":
            print(f"  WARNING {path}: mode is {got:04o}, wanted {mode:04o}")
    except OSError as e:
        print(f"  WARNING {path}: could not set mode ({e})")


def _load_ca(d):
    kp, cp = os.path.join(d, "ca.key"), os.path.join(d, "ca.crt")
    if not (os.path.exists(kp) and os.path.exists(cp)):
        sys.exit(f"no CA in {d}; run init-ca first")
    with open(kp, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(cp, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    return key, cert


def _fpr(cert):
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def init_ca(args):
    d = args.dir
    if os.path.exists(os.path.join(d, "ca.key")) and not args.force:
        sys.exit(f"CA already exists in {d}; --force to replace "
                 "(this invalidates every certificate it has issued)")
    _secure_dir(d)
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.org),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    _write(os.path.join(d, "ca.key"),
           key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()), 0o600)
    _write(os.path.join(d, "ca.crt"),
           cert.public_bytes(serialization.Encoding.PEM), 0o644)
    print(f"CA created in {d}")
    print(f"  subject     {cert.subject.rfc4514_string()}")
    print(f"  valid until {cert.not_valid_after_utc:%Y-%m-%d}")
    print(f"  sha256      {_fpr(cert)}")
    print()
    print("Install ca.crt as a trusted root on the machines that will talk to")
    print("the panel. ca.key never leaves this directory and never goes on the")
    print("panel -- only the leaf does.")


def issue(args):
    d = args.dir
    ca_key, ca_cert = _load_ca(d)
    out = args.out or os.path.join(d, "issued", args.ip.replace(":", "_"))
    _secure_dir(out)

    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)

    # The panel has no DNS name, so the SAN is an IP literal. Browsers and
    # python ssl both accept an IP SAN; a CN alone has not been honoured for
    # years, so the SAN is the part that matters.
    sans = [x509.IPAddress(__import__("ipaddress").ip_address(args.ip))]
    for extra in args.dns or []:
        sans.append(x509.DNSName(extra))

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.ip)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_cert.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    _write(os.path.join(out, "server.key"),
           key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()), 0o600)
    _write(os.path.join(out, "server.crt"), leaf_pem, 0o644)
    # chain = leaf + issuing CA. The root is omitted deliberately: a client that
    # does not already trust the root will not be persuaded by us shipping it.
    _write(os.path.join(out, "chain.pem"), leaf_pem + ca_pem, 0o644)

    meta = {
        "issuer": ca_cert.subject.rfc4514_string(),
        "subject": cert.subject.rfc4514_string(),
        "serial": f"{cert.serial_number:x}",
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256": _fpr(cert),
        "san": [args.ip] + list(args.dns or []),
        "source": "tuxedo-ca.py, workstation-generated",
        "key": "EC P-256",
    }
    _write(os.path.join(out, "meta.json"),
           (json.dumps(meta, indent=2) + "\n").encode(), 0o644)

    print(f"issued for {args.ip} into {out}")
    print(f"  serial      {meta['serial']}")
    print(f"  valid until {cert.not_valid_after_utc:%Y-%m-%d} ({args.days} days)")
    print(f"  sha256      {meta['sha256']}")
    print()
    print("Push with tls/tuxedo-tls-push.py, which verifies by reconnecting and")
    print("asserting the served certificate matches this fingerprint.")


def show(args):
    d = args.dir
    _, ca_cert = _load_ca(d)
    print(f"CA  {ca_cert.subject.rfc4514_string()}")
    print(f"    valid until {ca_cert.not_valid_after_utc:%Y-%m-%d}")
    print(f"    sha256 {_fpr(ca_cert)}")
    issued = os.path.join(d, "issued")
    if not os.path.isdir(issued):
        print("\nno leaves issued yet")
        return
    now = dt.datetime.now(dt.timezone.utc)
    print("\nissued:")
    for entry in sorted(os.listdir(issued)):
        mp = os.path.join(issued, entry, "meta.json")
        if not os.path.exists(mp):
            continue
        m = json.load(open(mp, encoding="utf-8"))
        na = dt.datetime.fromisoformat(m["not_after"])
        left = (na - now).days
        flag = "  EXPIRED" if left < 0 else ("  expires soon" if left < 30 else "")
        print(f"  {entry:20} until {na:%Y-%m-%d}  {left:>5}d{flag}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_dir = os.path.join(os.path.expanduser("~"), ".tuxedo-ca")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("init-ca", help="create the owner CA (once)")
    a.add_argument("--dir", default=default_dir)
    a.add_argument("--name", default="Tuxedo Owner CA")
    a.add_argument("--org", default="Tuxedo Touch")
    a.add_argument("--force", action="store_true")
    a.set_defaults(fn=init_ca)

    b = sub.add_parser("issue", help="issue a leaf for the panel")
    b.add_argument("--dir", default=default_dir)
    b.add_argument("--ip", required=True, help="the panel's IP; becomes the SAN")
    b.add_argument("--dns", action="append", help="extra DNS SAN (repeatable)")
    b.add_argument("--days", type=int, default=LEAF_DAYS)
    b.add_argument("--out")
    b.set_defaults(fn=issue)

    c = sub.add_parser("show", help="list the CA and what it has issued")
    c.add_argument("--dir", default=default_dir)
    c.set_defaults(fn=show)

    args = ap.parse_args()
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
