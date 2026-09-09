#!/bin/bash
# Production proof: does cmd=141 still leak ON THE PANEL after LEAKS 24 and 26?
#
# The per-request results so far are all from the emulated bench. This drives the
# real unit and reads VmRSS either side. RSS is page-quantised at 4 kB, so it can
# only see a leak of roughly 14 B/request or more over 300 requests -- which is
# exactly the range that matters here: the pre-fix rate was about 107 B/request,
# i.e. ~32 kB or 8 pages over 300 requests, comfortably visible. Zero growth is
# therefore a real result at this sample size, and a small non-zero one would not
# be.
#
# Costs 2 of the panel's 10 session slots (one login per scenedrive invocation),
# reaped when the sessions idle out after 10 minutes. Writes nothing: cmd=141 on a
# scene id that does not exist returns before writeSceneNode.
set -u
N="${1:-300}"
: "${PANEL_USER:?set PANEL_USER}"
PANEL="${PANEL:-203.0.113.5}"   # the real address is not in this repo; override via env
VMHOST="${VMHOST:-203.0.113.40}"   # build VM; the real address is not in this repo
KEY=~/.ssh/tuxedo_ed25519
SSH="ssh -o ConnectTimeout=30 -o BatchMode=yes -i $KEY root@$PANEL"

rss() {
    $SSH 'export PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH; for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null); case "$e" in *Barracuda*) grep VmRSS /proc/${p#/proc/}/status | tr -s " " | cut -d" " -f2;; esac; done'
}

echo "  binary: $($SSH 'md5sum /opt/webserver/Barracuda | cut -c1-8')"
echo "  warming $N (excludes the startup ramp from the measurement)"
sudo=""
ssh -o ConnectTimeout=25 -i ~/.ssh/fwbuild_ed25519 -o IdentitiesOnly=yes claude@${VMHOST:-203.0.113.40} \
  "cd /work/fwcheck && sudo TUXEDO_USER=$PANEL_USER python3 /tmp/scenedrive.py $PANEL $PANEL_USER 141 $N sceneid=1" \
  2>&1 | grep -E "hiddenKey|body sizes" | sed 's/^/    /'

BEFORE=$(rss)
echo "  VmRSS before: $BEFORE kB"

ssh -o ConnectTimeout=25 -i ~/.ssh/fwbuild_ed25519 -o IdentitiesOnly=yes claude@${VMHOST:-203.0.113.40} \
  "cd /work/fwcheck && sudo TUXEDO_USER=$PANEL_USER python3 /tmp/scenedrive.py $PANEL $PANEL_USER 141 $N sceneid=1" \
  2>&1 | grep -E "body sizes" | sed 's/^/    /'

AFTER=$(rss)
echo "  VmRSS after:  $AFTER kB"
echo "  delta: $((AFTER - BEFORE)) kB over $N requests"
echo "  (pre-fix would have been about $((N * 107 / 1024)) kB)"
