#!/bin/bash
# Size the REMAINING leak in production: does /GetSceneList really cost 733 B per
# request on the panel, and how fast would that matter?
#
# This is the number that decides whether an allocator rework earns its risk. The
# bench says 733 B/request. If that holds on the panel and the scene page polls,
# the hourly cost is what makes it urgent or not.
#
# Uses the API surface, which authenticates with the authtoken/HMAC scheme over
# TLS. Read-only: operation=get.
#
# Runs at two request counts, because a per-login constant divided by N looks
# exactly like a small per-request leak, and that mistake has already been made
# twice today.
set -u
: "${PANEL_USER:?set PANEL_USER}"
PANEL="${PANEL:-203.0.113.5}"   # the real address is not in this repo; override via env
VM="ssh -o ConnectTimeout=25 -i $HOME/.ssh/fwbuild_ed25519 -o IdentitiesOnly=yes claude@${VMHOST:-203.0.113.40}"
VMHOST="${VMHOST:-203.0.113.40}"   # build VM; the real address is not in this repo
PSSH="ssh -o ConnectTimeout=30 -o BatchMode=yes -i $HOME/.ssh/tuxedo_ed25519 root@$PANEL"

rss() {
    $PSSH 'export PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH; for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null); case "$e" in *Barracuda*) grep VmRSS /proc/${p#/proc/}/status | tr -s " " | cut -d" " -f2;; esac; done'
}

for N in 300 900; do
    echo "=== /GetSceneList on the panel, N=$N ==="
    B=$(rss)
    $VM "cd /work/fwcheck && sudo timeout 900 python3 leakprobe.py --host $PANEL --mode api \
         --endpoint /GetSceneList --plain operation=get \
         --user $PANEL_USER --creds /tmp/pw.txt --warmup 0 --n $N --every 100" 2>&1 \
      | grep -E "measured statuses|slope|rss" | sed 's/^/    /'
    A=$(rss)
    echo "    panel VmRSS $B -> $A kB   delta $((A - B)) kB over $N requests"
done
