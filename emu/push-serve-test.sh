#!/bin/bash
# Prove `tuxweb --serve` serves the push stream from IPC end to end: a client
# subscribes, is handed the CURRENT state from the model (snapshot, no re-500),
# and then receives a LIVE frame pushed after it connected. Real kernel queues,
# fake /tuxedo, no Barracuda, no panel. Runs on the build VM as root.
#
# This is stage 8c's push path. What it does NOT cover: TLS (proven in stage 3),
# the 80->301 leg (redirect.rs, unit-tested), the typed API (api.rs), and the
# auth gate on the push path (§4.10.1) -- those layer onto this serve mode.
#
#   sudo bash emu/push-serve-test.sh
#   BIN=/path/to/tuxweb sudo -E bash emu/push-serve-test.sh
set -u
BIN=${BIN:-/work/tuxweb-8a/target/debug/tuxweb}
HERE=$(cd "$(dirname "$0")" && pwd)
CHK="$HERE/push_capture_check.py"
QA=/tmp/quickarmstate-test
OUT=/tmp/pushserve.out
PORT=48080
RPORT=48081
fail=0
say() { echo; echo "=== $* ==="; }

[ -x "$BIN" ] || { echo "ABORT: no tuxweb at $BIN (set BIN=...)"; exit 1; }
[ -f "$CHK" ] || { echo "ABORT: no $CHK"; exit 1; }

say "0. quickarmstate fixture: partition 1 -> 2"
printf '2 0 0 0 0 0 0 0\n' > "$QA"

say "1. create both queues at the panel geometry"
python3 "$CHK" mkqueues || { python3 "$CHK" unlink; exit 1; }

say "2. fake /tuxedo, then tuxweb --serve, then a client that subscribes"
echo "   the fake tuxedo registers the panel as Ready on the 500, then pushes a"
echo "   LIVE Armed frame ~2.5s later -- after the client has connected"
python3 "$CHK" serve_tux 22 & TUX=$!
sleep 0.5
TUXWEB_REDIRECT_BIND="127.0.0.1:$RPORT" "$BIN" --serve 4242 "127.0.0.1:$PORT" 16 "$QA" > /tmp/serve.log 2>&1 & SRV=$!
sleep 2                                   # let 500 + 504 + Ready settle into the model
rm -f "$OUT"
python3 "$CHK" client "127.0.0.1:$PORT" 7 "$OUT"   # live Armed arrives while reading

say "2b. capability endpoint on a separate connection, while serve is still up"
python3 "$CHK" apiget "127.0.0.1:$PORT" "/system_http_api/API_REV01/GetCapabilities" '"contract":1' || fail=1

say "2c. the 80->301 leg preserves the path"
python3 "$CHK" redirectget "127.0.0.1:$RPORT" "/authenticated/tuxedoapi.html?url=x" || fail=1

wait "$SRV" 2>/dev/null                    # let tuxweb finish its window and send 501
wait "$TUX" 2>/dev/null

say "3. tuxweb serve log"
sed 's/^/   /' /tmp/serve.log

say "4. verify: preamble, snapshot (504 + Ready), then the LIVE Armed frame"
python3 "$CHK" verify_serve "$OUT" || fail=1

say "5. cleanup"
python3 "$CHK" unlink
rm -f "$QA" "$OUT" /tmp/serve.log

echo
[ "$fail" = 0 ] && echo "OK push-serve" || echo "FAIL push-serve"
exit "$fail"
