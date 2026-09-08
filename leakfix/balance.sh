#!/bin/bash
# Allocation/free balance sheet for one request, by PLT.
#
# The remaining 39 B/request is 32-byte chunks holding POINTERS, not text, so
# chunkdiff cannot name it from contents the way it named the page map. Counting
# every allocator and its matching free per request names the FAMILY first, which
# narrows where to look for the site.
#
# Traced with a comma-separated dfilter over each PLT entry (4 bytes is enough --
# entering the PLT is the call). Ten requests, so a per-request rate is readable
# rather than inferred from one.
set -u
N="${1:-10}"
: "${PANEL_USER:?set PANEL_USER}"

# name:addr, allocators then their frees
PLTS="json_delete:ba18 json_as_string:bc34 json_free:bca0 malloc:bcac \
new_array:bed4 json_new_a:bfe8 free:c150 delete_array:c168 json_new:c39c \
delete_scalar:c3cc"

FILTER=""
for p in $PLTS; do
    a=${p##*:}
    FILTER="$FILTER,0x$a..0x$((0x$a+4))"
done
FILTER=${FILTER#,}

sudo bash /work/fwcheck/serve-traced.sh /work/emu/scenes "$FILTER" /trace.log > /tmp/bal.serve 2>&1
tail -1 /tmp/bal.serve

cd /work/fwcheck
sudo truncate -s 0 /work/emu/scenes/trace.log
sudo TUXEDO_USER="$PANEL_USER" python3 /tmp/scenedrive.py 127.0.0.1 "$PANEL_USER" \
    141 "$N" "sceneid=1" 2>&1 | grep -E "body sizes" | sed 's/^/  /'

echo "  --- calls per $N requests, and per request ---"
for p in $PLTS; do
    name=${p%%:*}; a=${p##*:}
    pat=$(printf "%016x" "0x$a")
    c=$(sudo grep -a -c "/$pat/" /work/emu/scenes/trace.log 2>/dev/null || echo 0)
    printf "    %-14s %5d   %6.2f/req\n" "$name" "$c" "$(echo "$c $N" | awk '{print $1/$2}')"
done
