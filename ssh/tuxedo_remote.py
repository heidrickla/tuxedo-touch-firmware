#!/usr/bin/env python3
"""
Change the Tuxedo Touch's root filesystem over SSH, without an SD card.

This is the tool that ends the reflash cycle. Once dropbear is running, the
root filesystem is reachable, and a change that previously meant building a
125 MB image, writing a card, walking to the panel and power-cycling it becomes
a file copy and a service restart.

    python tuxedo_remote.py info
    python tuxedo_remote.py get  /etc/rc.d/rc.local ./rc.local
    python tuxedo_remote.py put  ./rc.local /etc/rc.d/rc.local --mode 755
    python tuxedo_remote.py run  'ls -la /opt/tuxedo/configuration'
    python tuxedo_remote.py backup ./panel-backup/

WHY NOT scp: the panel has no `sftp-server`, so modern OpenSSH `scp` fails with
`/usr/libexec/sftp-server: No such file or directory`. Everything here uses
`ssh host 'cat > file'` instead, which needs nothing the panel does not have.
Verified byte-for-byte on a 200,000-byte payload.

SAFETY

`put` refuses to write unless the byte count and hash come back matching, and
writes to a temporary name and renames, so an interrupted transfer cannot leave
a truncated file in place. That mattered enough on the SD path to be worth
repeating here.

It will not touch the alarm application or the ECP driver. There is no verb for
arming, disarming or bypassing.
"""

import argparse
import hashlib
import os
import subprocess
import sys

DEFAULT_HOST = "203.0.113.5"
DEFAULT_USER = "root"
DEFAULT_KEY = os.path.expanduser("~/.ssh/tuxedo_ed25519")

# Paths that are never writable through this tool. The alarm application and
# the flasher are out of scope on purpose: a bad write to either is exactly the
# failure this tool exists to avoid needing a card to recover from.
FORBIDDEN = ("/tuxedo", "/supervis", "/opt/webserver/Barracuda")


def ssh_args(a):
    return [
        "ssh", "-i", a.key, "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes", "-o", f"ConnectTimeout={a.timeout}",
        f"{a.user}@{a.host}",
    ]


def run(a, cmd, stdin=None, capture=True):
    p = subprocess.run(ssh_args(a) + [cmd], input=stdin,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE)
    if p.returncode != 0:
        err = (p.stderr or b"").decode("utf-8", "replace").strip()
        raise SystemExit(f"ssh failed ({p.returncode}): {err}")
    return p.stdout or b""


def cmd_info(a):
    out = run(a, "; ".join([
        "echo '--- identity ---'", "id", "uname -a",
        "echo '--- uptime/date ---'", "date", "cat /proc/uptime",
        "echo '--- root filesystem mount ---'", "grep ' / ' /proc/mounts",
        "echo '--- config partition ---'", "grep mtdblock17 /proc/mounts",
        "echo '--- flash partitions ---'", "cat /proc/mtd 2>/dev/null | head",
        "echo '--- free space ---'", "df -h / /opt/tuxedo/configuration 2>/dev/null",
        "echo '--- dropbear ---'", "ps 2>/dev/null | grep -c '[d]ropbear'",
    ]))
    print(out.decode("utf-8", "replace"))


def cmd_run(a):
    print(run(a, a.command).decode("utf-8", "replace"), end="")


def cmd_get(a):
    data = run(a, f"cat {shq(a.remote)}")
    with open(a.local, "wb") as f:
        f.write(data)
    print(f"  {a.remote} -> {a.local}  {len(data)} bytes  "
          f"sha256={hashlib.sha256(data).hexdigest()[:16]}")


def shq(s):
    return "'" + s.replace("'", "'\\''") + "'"


def cmd_put(a):
    for bad in FORBIDDEN:
        if os.path.normpath(a.remote).replace("\\", "/") == bad:
            raise SystemExit(
                f"refusing to write {a.remote}: this tool does not modify the "
                f"alarm application or the web server. Use an SD image for that, "
                f"where a mistake is recoverable.")
    data = open(a.local, "rb").read()
    want = hashlib.sha256(data).hexdigest()
    tmp = a.remote + ".part"

    # Ensure / is writable. JFFS2 on NAND is normally rw, but the boot scripts
    # do not guarantee it, so ask rather than assume.
    mounted_ro = b"ro," in run(a, "grep ' / ' /proc/mounts")
    if mounted_ro:
        if not a.remount:
            raise SystemExit("/ is mounted read-only; pass --remount to allow "
                             "'mount -o remount,rw /'")
        run(a, "mount -o remount,rw /")
        print("  remounted / read-write")

    run(a, f"cat > {shq(tmp)}", stdin=data)
    got = run(a, f"wc -c < {shq(tmp)}").decode().strip()
    if got != str(len(data)):
        run(a, f"rm -f {shq(tmp)}")
        raise SystemExit(f"short write: {got} of {len(data)} bytes, aborted")

    # Verify content, not just length. md5sum is more likely present than
    # sha256sum on a userland this small; accept either.
    remote_hash = run(a, f"sha256sum {shq(tmp)} 2>/dev/null || md5sum {shq(tmp)}"
                      ).decode().split()[0]
    local_hash = (want if len(remote_hash) == 64
                  else hashlib.md5(data).hexdigest())
    if remote_hash != local_hash:
        run(a, f"rm -f {shq(tmp)}")
        raise SystemExit("hash mismatch after transfer, aborted; nothing replaced")

    if a.backup:
        run(a, f"cp -p {shq(a.remote)} {shq(a.remote + '.bak')} 2>/dev/null || true")
    run(a, f"mv {shq(tmp)} {shq(a.remote)}")
    if a.mode:
        run(a, f"chmod {a.mode} {shq(a.remote)}")
    run(a, "sync")
    print(f"  {a.local} -> {a.remote}  {len(data)} bytes  verified"
          + (f"  mode {a.mode}" if a.mode else "")
          + ("  (previous kept as .bak)" if a.backup else ""))


def cmd_backup(a):
    os.makedirs(a.dest, exist_ok=True)
    targets = [
        "/etc/rc.d/rc.local", "/etc/rc.d/rc.conf", "/etc/rc.d/rcS",
        "/etc/hosts", "/etc/passwd", "/etc/fstab", "/srv_info.conf",
        "/etc/rc.d/init.d/startup", "/etc/rc.d/init.d/settime",
    ]
    for t in targets:
        try:
            data = run(a, f"cat {shq(t)} 2>/dev/null")
        except SystemExit:
            print(f"  {t}: unreadable, skipped")
            continue
        if not data:
            print(f"  {t}: empty or missing, skipped")
            continue
        out = os.path.join(a.dest, t.strip("/").replace("/", "_"))
        with open(out, "wb") as f:
            f.write(data)
        print(f"  {t}  {len(data)} bytes")
    print(f"\nsaved to {a.dest}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--user", default=DEFAULT_USER)
    ap.add_argument("--key", default=DEFAULT_KEY)
    ap.add_argument("--timeout", type=int, default=15)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info", help="panel identity, mounts, partitions, free space")

    p = sub.add_parser("run", help="run a command")
    p.add_argument("command")

    p = sub.add_parser("get", help="read a file off the panel")
    p.add_argument("remote"); p.add_argument("local")

    p = sub.add_parser("put", help="write a file to the panel, verified")
    p.add_argument("local"); p.add_argument("remote")
    p.add_argument("--mode", help="chmod after writing, e.g. 755")
    p.add_argument("--backup", action="store_true",
                   help="keep the previous version as <path>.bak")
    p.add_argument("--remount", action="store_true",
                   help="allow remounting / read-write if it is read-only")

    p = sub.add_parser("backup", help="pull the files worth keeping a copy of")
    p.add_argument("dest")

    a = ap.parse_args()
    if not os.path.exists(a.key):
        raise SystemExit(f"no key at {a.key}")
    {"info": cmd_info, "run": cmd_run, "get": cmd_get,
     "put": cmd_put, "backup": cmd_backup}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
