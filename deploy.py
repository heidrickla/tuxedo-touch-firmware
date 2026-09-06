#!/usr/bin/env python3
"""Push the difference between a built image tree and the live panel, over SSH.

The rootfs is JFFS2 mounted rw, so changes persist across reboots. A 125 MB
flash is only needed to make a change survive the NEXT flash, or to alter
something that cannot be written while running. Everything else goes over SSH
in seconds.

    python deploy.py                  dry run, show what differs
    python deploy.py --apply          push the differences
    python deploy.py --apply busybox  only paths matching a substring

Dry run is the default on purpose: this writes to a live alarm panel.

This was a shell script first. Getting a file list out of `wsl.exe -- bash -c`
and back through ssh meant three layers of quoting, and every "$f" arrived
empty, so the comparison silently compared nothing and reported everything as
changed. Python removes the quoting problem rather than working around it.
"""
import argparse
import os
import subprocess
import sys

# /work/current is a symlink on the build VM pointing at the CURRENT build
# tree, so this default does not go stale at the next version. The old default
# was /work/root_patched, which no longer exists; the nearest surviving tree,
# /work/extracted/root_patched, carries a v9-era Barracuda (197b7e41), so a
# stale default here would have pushed nine-version-old binaries onto the panel.
TREE = os.environ.get("TREE", "/work/current")
HOST = os.environ.get("HOST", "203.0.113.5")
KEY = os.environ.get("KEY", os.path.expanduser("~/.ssh/tuxedo_ed25519"))
# The build VM, not WSL -- see TRAPS.md section 5.
BUILDER = os.environ.get("BUILDER", "vm")
VM = os.environ.get("VM", "claude@203.0.113.40")
VMKEY = os.environ.get("VMKEY", os.path.expanduser("~/.ssh/fwbuild_ed25519"))

SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes", "-o", "LogLevel=ERROR"]

# Only what we add or modify. Derived from the image rather than by diffing
# 3,500 files, so this can never propose overwriting something we did not put
# there.
PATHS = """bin/busybox sbin/syslogd sbin/klogd usr/local/bin
 usr/sbin/dropbear usr/sbin/dropbearkey usr/sbin/dropbear.musl
 usr/sbin/dropbearkey.musl bin/ntpclient etc/tuxedo-build etc/hosts
 etc/hosts.ota-notes etc/passwd etc/group etc/shadow etc/sysconfig/syslog
 etc/rc.d/rc.local etc/rc.d/rc.conf etc/rc.d/init.d/startup
 root/.ssh/authorized_keys etc/dropbear
 supervis opt/webserver/Barracuda""".split()


def builder(script, binary=False):
    """Run a shell script where the image tree lives. Passed on stdin, so no
    quoting survives to be mangled."""
    if BUILDER == "wsl":
        cmd = ["wsl.exe", "-d", "Debian", "--", "bash", "-s"]
    elif BUILDER == "vm":
        cmd = ["ssh", "-i", VMKEY] + SSH_OPTS + [VM, "sudo bash -s"]
    else:
        cmd = ["bash", "-s"]
    p = subprocess.run(cmd, input=script.encode(), capture_output=True)
    return p.stdout if binary else p.stdout.decode("utf-8", "replace")


def panel(script, binary=False):
    """Run a shell script on the panel, script on stdin."""
    cmd = ["ssh", "-i", KEY] + SSH_OPTS + [f"root@{HOST}", "sh -s"]
    p = subprocess.run(cmd, input=script.encode(), capture_output=True)
    return p.stdout if binary else p.stdout.decode("utf-8", "replace")


def panel_write(remote_path, blob, mode):
    """Send a file. The command goes as an ssh ARGUMENT and the bytes go on
    stdin -- they cannot share stdin. Getting this wrong sent the binary to
    `sh -s` as if it were a script, so nothing was written and, because the
    exit status was never checked, deploy reported success anyway.

    Writes to a temporary name and renames: writing over a binary that is
    currently executing gives ETXTBSY, but rename works."""
    d = os.path.dirname(remote_path)
    cmd = ["ssh", "-i", KEY] + SSH_OPTS + [
        f"root@{HOST}",
        f'mkdir -p "{d}" && cat > "{remote_path}.new" && '
        f'chmod {mode} "{remote_path}.new" && '
        f'mv "{remote_path}.new" "{remote_path}" && sync']
    p = subprocess.run(cmd, input=blob, capture_output=True)
    if p.returncode != 0:
        raise SystemExit(f"  FAILED writing {remote_path}: "
                         f"rc={p.returncode} {p.stderr.decode('utf-8','replace').strip()}")
    return True


def parse(text):
    """path -> ('L', target) or ('F', md5, mode)"""
    out = {}
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 2 or not parts[0]:
            continue
        out[parts[0]] = tuple(parts[1:])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("filter", nargs="?", default="")
    a = ap.parse_args()

    print(f"tree    {TREE} ({BUILDER})")
    print(f"panel   {HOST}")
    for line in panel("head -2 /etc/tuxedo-build 2>/dev/null").splitlines():
        print("  " + line)

    local = parse(builder(rf"""
cd {TREE} || exit 1
find {' '.join(PATHS)} \( -type f -o -type l \) 2>/dev/null | sort | while read -r f; do
    if [ -L "$f" ]; then printf '%s|L|%s\n' "$f" "$(readlink "$f")"
    else printf '%s|F|%s|%s\n' "$f" "$(md5sum "$f" | cut -d' ' -f1)" "$(stat -c%a "$f")"; fi
done
"""))
    if not local:
        print("  no files found in the tree; is TREE correct?")
        return 1

    # The panel rewrites /etc/hosts at boot (network(8) substitutes the real
    # gateway), so it always differs from the image and pushing ours back would
    # undo that. Skip it unless asked for by name.
    skip = set() if a.filter else {"etc/hosts"}
    names = [f for f in local if a.filter in f and f not in skip]
    remote = parse(panel("\n".join(
        f'if [ -L "/{f}" ]; then printf \'{f}|L|%s\n\' "$(readlink "/{f}")";'
        f' elif [ -f "/{f}" ]; then printf \'{f}|F|%s\n\' "$(md5sum "/{f}" | cut -d\' \' -f1)";'
        f' else printf \'{f}|MISSING\n\'; fi' for f in names)))

    todo, new, changed, same = [], 0, 0, 0
    for f in sorted(names):
        lv = local[f]
        rv = remote.get(f)
        if rv is None or rv[0] == "MISSING":
            print(f"  NEW      /{f}" + (f" -> {lv[1]}" if lv[0] == "L" else ""))
            new += 1
            todo.append(f)
        elif lv[0] != rv[0] or lv[1] != rv[1]:
            extra = f" -> {lv[1]} (was {rv[1] if len(rv) > 1 else '?'})" if lv[0] == "L" else ""
            print(f"  CHANGED  /{f}{extra}")
            changed += 1
            todo.append(f)
        else:
            same += 1

    print("  ---")
    print(f"  {new} new, {changed} changed, {same} already match")
    if not a.apply:
        print("\ndry run. re-run with --apply to push.")
        return 0
    if not todo:
        print("\nnothing to do.")
        return 0

    print("\npushing...")
    for f in todo:
        lv = local[f]
        d = os.path.dirname("/" + f)
        if lv[0] == "L":
            panel(f'mkdir -p "{d}" && ln -sf "{lv[1]}" "/{f}"')
            print(f"  link  /{f} -> {lv[1]}")
        else:
            mode = lv[2] if len(lv) > 2 else "644"
            blob = builder(f"cat {TREE}/{f}", binary=True)
            if not blob:
                raise SystemExit(f"  FAILED reading {TREE}/{f} from the builder")
            panel_write(f"/{f}", blob, mode)
            print(f"  file  /{f} ({mode}, {len(blob)} bytes)")

    print("\nverifying...")
    os.execvp("bash", ["bash", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "verify-panel.sh"), HOST, KEY])


if __name__ == "__main__":
    sys.exit(main())
