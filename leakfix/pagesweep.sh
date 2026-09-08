#!/bin/bash
# Sweep every servable page for a per-request leak.
#
# The IPC hunt started because HTTP-only testing measured zero and the panel
# still grew. This is the converse: the API paths measure zero, so sweep the
# pages nobody has driven and find out which of them leak.
#
# Each page gets a warmup then a measured run, because the startup working-set
# ramp is steep enough to dominate a short run entirely and read as a leak.
# /tuxedoapi.html is included as a NEGATIVE CONTROL: it is known-clean, so if it
# reads non-zero the instrument is wrong and every other row is void.
#
# EXCLUDED deliberately:
#   armcontrol.html   can arm/disarm - side effects
#   exit.html, logout.html, SessionPage.html   end the session mid-sweep
#   Invalid.html, Msg404.html   error pages, not real handlers
set -u
N="${1:-200}"
W="${2:-200}"
cd /work/fwcheck

PAGES="/tuxedoapi.html /index.html /home.html /console.html /consolekeypad.html
/devicelist.html /groups.html /occupancy.html /multipartition.html /pList.html
/bookmarksView.html /camerasetup.html /camaddedit.html /camsingleview.html
/videoplayback.html /videoscreen.html /zwavedevicelist.html
/scene_configuration.html /mobileview.html /eventhandler.html"

printf "  %-30s %8s %10s  %s\n" PAGE STATUS "B/req" NOTE
for p in $PAGES; do
    out=$(sudo timeout 600 python3 leakprobe.py --host 127.0.0.1 --mode console \
            --path "$p" --warmup "$W" --n "$N" --every 50 2>&1)
    slope=$(echo "$out" | grep -oE "slope +: [-0-9.]+" | grep -oE "[-0-9.]+$")
    st=$(echo "$out" | grep -oE "measured statuses: \{.*\}" | sed 's/measured statuses: //')
    note=""
    case "$st" in
        *"200: $N"*) ;;                       # all good
        *) note="<-- NOT all 200, result is void" ;;
    esac
    printf "  %-30s %8s %10s  %s\n" "$p" "${st:-?}" "${slope:-?}" "$note"
done
echo
echo "  A page that did not return 200 for every request exercised nothing and"
echo "  its number means nothing. /tuxedoapi.html must read 0.0 or the sweep is void."
