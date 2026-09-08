#!/bin/bash
# Which page wedges the webserver, and does it wedge the UNPATCHED build too?
#
# The page sweep failed on its last four pages and that looked like the
# documented "wedges under sustained load". It is not: running
# /zwavedevicelist.html FIRST on a freshly started server wedges it within a
# couple of hundred requests. So a specific page hangs the server and its
# position in the sweep was a coincidence.
#
# Usage: wedgetest.sh <tree> <label>
set -u
TREE="${1:-/work/emu/p15ipc5}"
LABEL="${2:-wedge}"
cd /work/fwcheck

for p in /proc/[0-9]*; do
    e=$(sudo readlink "$p/exe" 2>/dev/null)
    case "$e" in *qemu-arm-static) sudo kill -9 "${p#/proc/}" 2>/dev/null ;; esac
done
sleep 3
sudo bash emu/serve.sh "$TREE" "$LABEL" 2>&1 | tail -1 | sed 's/^/  /'
echo -n "  binary: "; sudo md5sum "$TREE/opt/webserver/Barracuda" | cut -c1-8

alive() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1/; }
echo "  baseline GET / -> $(alive)"

for p in /zwavedevicelist.html /mobileview.html /eventhandler.html; do
    echo "=== $p ==="
    # A small number of requests: if the page wedges, it does so quickly.
    out=$(sudo timeout 120 python3 leakprobe.py --host 127.0.0.1 --mode console \
            --path "$p" --warmup 20 --n 20 --every 10 2>&1)
    echo "$out" | grep -E "measured statuses|slope" | sed 's/^/    /'
    echo "$out" | grep -qE "TimeoutError|timed out" && echo "    *** TIMED OUT ***"
    echo "    GET / after -> $(alive)"
done
echo DONE-WEDGETEST
