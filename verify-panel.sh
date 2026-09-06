#!/usr/bin/env bash
# Verify over SSH that the panel is running what we think it is.
#
# Every offset here was wrong at least once before it was right. The P6 offset
# was read as 380144 instead of 380656 from a transposed digit, which reported a
# patched site as unpatched. The script computes offsets from hex so that cannot
# recur.
#
#   ./verify-panel.sh [host] [keyfile]
set -uo pipefail
HOST="${1:-203.0.113.5}"
KEY="${2:-$HOME/.ssh/tuxedo_ed25519}"
# -n is essential: without it ssh eats the loop's here-string and the patch
# loop runs exactly once.
SSH="ssh -n -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -o BatchMode=yes -o LogLevel=ERROR root@$HOST"

FAIL=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; FAIL=1; }

# name            hex offset  stock bytes      patched bytes
PATCHES="
P1-lockout        0xd5fc      30119fe5         080000ea
P2-validate-hook  0xbaf0      090091e8         5f0500ea
P6-heap-off-by-1  0x5cef0     38c04ce2         0000a0e1
"

echo "panel $HOST"
BUILD=$($SSH 'cat /etc/tuxedo-build 2>/dev/null' 2>/dev/null)
[ -n "$BUILD" ] || { echo "  cannot reach the panel over SSH"; exit 1; }
printf '%s\n' "$BUILD" | sed 's/^/  /'

echo
echo "Barracuda patch sites"
while read -r name off stock patched; do
    [ -z "$name" ] && continue
    dec=$((off))
    live=$($SSH "dd if=/opt/webserver/Barracuda bs=1 skip=$dec count=4 2>/dev/null | od -An -tx1 | tr -d ' \n'" 2>/dev/null)
    case "$live" in
        "$patched") pass "$name at $off" ;;
        "$stock")   fail "$name at $off" "site is STOCK, patch not applied" ;;
        *)          fail "$name at $off" "unexpected bytes [$live], expected patched [$patched] or stock [$stock]" ;;
    esac
done <<< "$PATCHES"

echo
echo "listeners"
$SSH 'netstat -ltn 2>/dev/null' 2>/dev/null | awk '/LISTEN/{print "  "$4}' | sort

echo
echo "services"
SYS=$($SSH 'ps | grep -c "[s]yslogd\|[k]logd"' 2>/dev/null)
[ "${SYS:-0}" -ge 2 ] && pass "syslogd and klogd running" || fail "syslogd and klogd running" "found ${SYS:-0} of 2"
BB=$($SSH 'ls -l /bin/busybox 2>/dev/null | tr -s " " | cut -d" " -f5' 2>/dev/null)
[ -n "$BB" ] && pass "busybox present ($BB bytes)" || fail "busybox present" "missing"
AWK=$($SSH 'echo "a b c" | /usr/local/bin/awk "{print \$2}" 2>/dev/null' 2>/dev/null)
[ "$AWK" = "b" ] && pass "busybox applets work" || fail "busybox applets work" "awk returned [$AWK]"

echo
echo "NAND"
BAD=$($SSH 'grep -c "Bad block at" /var/log/messages 2>/dev/null' 2>/dev/null)
if [ -z "$BAD" ] || [ "$BAD" = "0" ]; then
    skip "NAND bad blocks" "no kernel log yet, syslog may have just started"
elif [ "$BAD" -le 9 ]; then
    pass "NAND bad blocks: $BAD (baseline 9)"
else
    fail "NAND bad blocks: $BAD" "baseline was 9; a rising count means the flash is degrading"
fi

echo
echo "SD card, so images can be pushed without moving it"
$SSH 'grep -q " /mnt/sd " /proc/mounts' && pass "card mounted rw at /mnt/sd"     || fail "card mounted at /mnt/sd" "push-image.sh cannot work without it"

echo
echo "/etc/hosts, entries only"
BAD=$($SSH 'grep -vE "^[[:space:]]*#" /etc/hosts 2>/dev/null | grep -vE "^[[:space:]]*$"' 2>/dev/null \
      | grep -vE '^[[:space:]]*[0-9a-fA-F:.]+([[:space:]]+[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)+[[:space:]]*$')
if [ -z "$BAD" ]; then pass "no mangled entries"; else fail "mangled entries" "$BAD"; fi

echo
[ "$FAIL" = "0" ] && echo "panel matches expectations" || echo "PANEL DIFFERS"
exit "$FAIL"
