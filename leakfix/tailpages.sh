#!/bin/bash
# Measure the four pages the earlier sweep never reached, plus the control.
#
# The sweep wedged the server before it got to them, on BOTH builds, so their
# "0.0" in that table was the absence of a measurement rather than a clean
# result. These run FIRST on a fresh server so the wedge cannot reach them.
set -u
cd /work/fwcheck
for p in /zwavedevicelist.html /mobileview.html /eventhandler.html \
         /scene_configuration.html /tuxedoapi.html; do
    out=$(sudo timeout 600 python3 leakprobe.py --host 127.0.0.1 --mode console \
            --path "$p" --warmup 200 --n 200 --every 50 2>&1)
    slope=$(echo "$out" | grep -oE "slope +: [-0-9.]+" | grep -oE "[-0-9.]+$")
    st=$(echo "$out" | grep -oE "measured statuses: \{.*\}" | sed 's/measured statuses: //')
    printf "  %-28s %-14s %s\n" "$p" "${st:-NO-OUTPUT}" "${slope:-?}"
done
echo DONE-TAILPAGES
