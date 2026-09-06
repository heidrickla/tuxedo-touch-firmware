#!/usr/bin/env bash
# Pull /opt/tuxedo/configuration off the panel into a canonical copy on the
# build VM, so the emulation trees can be seeded from it.
#
#   ./fetch-config.sh [panel-host] [vm-host]
#
# The panel has no tar, gzip, cpio or sftp-server, so this emits a
# length-prefixed stream -- "===F <size> <path>" then exactly <size> raw bytes
# -- which is binary-safe where a delimiter-only scheme is not.
#
# tls/ is EXCLUDED. It holds the panel's TLS private key, which is reissued
# from the owner CA rather than copied around. The two large logs are excluded
# because they are logs.
set -euo pipefail
PANEL="${1:-203.0.113.5}"
VM="${2:-claude@203.0.113.40}"
PKEY="${PKEY:-$HOME/.ssh/tuxedo_ed25519}"
VKEY="${VKEY:-$HOME/.ssh/fwbuild_ed25519}"
Q="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR"
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "listing $PANEL"
ssh -n -i "$PKEY" $Q "root@$PANEL" \
    'PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH; ls -1R /opt/tuxedo/configuration' \
    > "$TMP/listing.txt"

python3 - "$TMP/listing.txt" "$TMP/fetch.sh" <<'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
cur, files, dirs = None, [], set()
for ln in lines:
    ln = ln.rstrip()
    if not ln:
        continue
    if ln.endswith(":") and ln.startswith("/opt/tuxedo/configuration"):
        cur = ln[:-1]; dirs.add(cur); continue
    if cur:
        files.append(cur + "/" + ln)
files = [f for f in files if f not in dirs]
EXCLUDE = ("/tls/", "/SupervisionLog.txt", "/AuiEventLogFile.txt")
keep = [f for f in files if not any(x in f for x in EXCLUDE)]
with open(sys.argv[2], "w", newline="\n") as fh:
    fh.write("PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH\n")
    for f in keep:
        fh.write(f'S=$(wc -c < "{f}" 2>/dev/null || echo 0); '
                 f'printf "===F %s %s\n" "$S" "{f}"; cat "{f}" 2>/dev/null\n')
print(f"  {len(keep)} files to fetch, {len(files)-len(keep)} excluded")
PY

echo "fetching"
ssh -i "$PKEY" $Q "root@$PANEL" 'sh -s' < "$TMP/fetch.sh" > "$TMP/stream.bin"
echo "  $(wc -c < "$TMP/stream.bin") bytes"

echo "installing on $VM as /work/panel-config"
cat "$TMP/stream.bin"           | ssh -i "$VKEY" $Q "$VM" 'cat > /tmp/cfg-stream.bin'
cat "$HERE/unpack-config.py"    | ssh -i "$VKEY" $Q "$VM" 'cat > /tmp/unpack-config.py'
ssh -n -i "$VKEY" $Q "$VM" \
    'sudo rm -rf /work/panel-config && sudo mkdir -p /work/panel-config &&
     sudo python3 /tmp/unpack-config.py /tmp/cfg-stream.bin /work/panel-config'
echo "done. run.sh seeds each tree from /work/panel-config."
