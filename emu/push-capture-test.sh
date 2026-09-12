#!/bin/bash
# Prove `tuxweb --push-capture` GENERATES the legacy push stream from IPC replies,
# on real kernel message queues, against a fake /tuxedo -- no Barracuda, no panel.
#
# Stage 8a. Stage 6 proved a non-Barracuda process receives /tuxedo's replies;
# stage 7 proved the command send path; this proves the reply -> legacy-frame
# layer that replaces Barracuda's `gettuxedoIPCCommFunc`. What it CANNOT prove is
# how the real /tuxedo sequences its replies -- that is the panel. What it does
# prove is that, given the replies, tuxweb emits the exact frames the two capture
# fixtures showed the vendor emits, fillers and all.
#
#   sudo bash emu/push-capture-test.sh
#   BIN=/path/to/tuxweb sudo -E bash emu/push-capture-test.sh
set -u
BIN=${BIN:-/work/tuxweb-8a/target/release/tuxweb}
HERE=$(cd "$(dirname "$0")" && pwd)
CHK="$HERE/push_capture_check.py"
QA=/tmp/quickarmstate-test
OUT=/tmp/pushcap.out
fail=0
say() { echo; echo "=== $* ==="; }

[ -x "$BIN" ] || { echo "ABORT: no tuxweb at $BIN (set BIN=...)"; exit 1; }
[ -f "$CHK" ] || { echo "ABORT: no $CHK"; exit 1; }

say "0. quickarmstate fixture: partition 1 -> 2 (as §5.12 measured on the panel)"
printf '2 0 0 0 0 0 0 0\n' > "$QA"; cat "$QA"

say "1. create both queues at the panel geometry, from something other than tuxweb"
python3 "$CHK" mkqueues || { python3 "$CHK" unlink; exit 1; }

say "2. fake /tuxedo in the background, THEN tuxweb -- a responder started after"
echo "   the 500 would miss it, exactly as registerclient's real one answers at once"
rm -f "$OUT"
python3 "$CHK" serve 15 & TUX=$!
sleep 1
"$BIN" --push-capture 4242 6 "$OUT" "$QA"; rc=$?
echo "  tuxweb exit $rc"
wait "$TUX" 2>/dev/null

say "3. verify the generated stream frame-for-frame against the expected sequence"
python3 "$CHK" verify "$OUT" || fail=1

say "4. cleanup"
python3 "$CHK" unlink
rm -f "$QA" "$OUT"

[ "$rc" = 0 ] || { echo "  tuxweb did not exit clean (rc=$rc)"; fail=1; }
echo
[ "$fail" = 0 ] && echo "OK push-capture" || echo "FAIL push-capture"
exit "$fail"
