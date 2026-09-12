#!/bin/bash
# Prove `tuxweb --serve` end to end on real kernel queues, no Barracuda, no panel:
#
#   * the push stream is token-gated (401 without, subscribed with), and a
#     subscriber gets the CURRENT state from the model (no re-500) and then LIVE
#     frames;
#   * the typed API: GetCapabilities (no token), GetSecurityStatus (token),
#     ArmWithCode / DisarmWithCode (token, plaintext form body, user code at
#     +0x0C) which return Sucess only once the panel CONFIRMS by a state flip;
#   * the negatives: arm without a token is 401, arm without a code is 400;
#   * the 80->301 leg preserves the path.
#
# A reactive fake /tuxedo answers the 500 with a registration + Ready, turns an
# arm command into an Armed status and a disarm into Ready, and logs every
# command it received so the codes and the user code are asserted at the queue.
#
#   sudo bash emu/push-serve-test.sh
#   BIN=/path/to/tuxweb sudo -E bash emu/push-serve-test.sh
set -u
BIN=${BIN:-/work/tuxweb-8a/target/debug/tuxweb}
HERE=$(cd "$(dirname "$0")" && pwd)
CHK="$HERE/push_capture_check.py"
QA=/tmp/quickarmstate-test
TOK=/tmp/tuxweb-tokens-test.json
CMDLOG=/tmp/faketux-cmds.tsv
OUT=/tmp/pushserve.out
PORT=48080
RPORT=48081
API=/system_http_api/API_REV01
fail=0
say() { echo; echo "=== $* ==="; }
step() { "$@" || fail=1; }

[ -x "$BIN" ] || { echo "ABORT: no tuxweb at $BIN (set BIN=...)"; exit 1; }
[ -f "$CHK" ] || { echo "ABORT: no $CHK"; exit 1; }

say "0. fixtures: quickarmstate (partition 1 -> 2), and a fresh token store"
printf '2 0 0 0 0 0 0 0\n' > "$QA"
rm -f "$TOK" "$CMDLOG" "$OUT"
TOKEN=$("$BIN" --issue-token bench "$TOK" | sed -n '2p')
[ ${#TOKEN} -eq 64 ] || { echo "ABORT: could not issue a token (got '$TOKEN')"; exit 1; }
echo "  issued a 64-hex token; store: $("$BIN" --list-tokens "$TOK" | tr -s ' ')"

say "1. create both queues at the panel geometry"
python3 "$CHK" mkqueues || { python3 "$CHK" unlink; exit 1; }

say "2. reactive fake /tuxedo, then tuxweb --serve with the token store"
python3 "$CHK" serve_tux 40 "$CMDLOG" & TUX=$!
sleep 0.5
TUXWEB_TOKEN_STORE="$TOK" TUXWEB_REDIRECT_BIND="127.0.0.1:$RPORT" \
  "$BIN" --serve 4242 "127.0.0.1:$PORT" 24 "$QA" > /tmp/serve.log 2>&1 & SRV=$!
sleep 2                                   # let 500 + 504 + Ready settle into the model

say "3. push stream: denied without a token, subscribed with one (Cookie form)"
step python3 "$CHK" pushdeny "127.0.0.1:$PORT"
python3 "$CHK" client "127.0.0.1:$PORT" 14 "$OUT" "$TOKEN" & CLI=$!
sleep 1

say "4. GetCapabilities needs no token"
step python3 "$CHK" apicall GET "127.0.0.1:$PORT" "$API/GetCapabilities" - - 200 '"contract":1'

say "5. GetSecurityStatus (token): disarmed"
step python3 "$CHK" apicall GET "127.0.0.1:$PORT" "$API/GetSecurityStatus" - "$TOKEN" 200 '"armed":false'

say "6. ArmWithCode (token, plaintext form): Sucess only once the panel confirms"
step python3 "$CHK" apicall POST "127.0.0.1:$PORT" "$API/AdvancedSecurity/ArmWithCode" \
  'arming=stay&pID=1&ucode=1234&operation=set' "$TOKEN" 200 '"Response":"Command sent sucessfully"'
step python3 "$CHK" apicall GET "127.0.0.1:$PORT" "$API/GetSecurityStatus" - "$TOKEN" 200 '"armed":true'

say "7. DisarmWithCode (token): Sucess with disarm's own inner key"
step python3 "$CHK" apicall POST "127.0.0.1:$PORT" "$API/AdvancedSecurity/DisarmWithCode" \
  'pID=1&ucode=1234&operation=set' "$TOKEN" 200 '"Result":{"Result":"Disarmed"}'
step python3 "$CHK" apicall GET "127.0.0.1:$PORT" "$API/GetSecurityStatus" - "$TOKEN" 200 '"armed":false'

say "8. negatives: no token -> 401, no user code -> 400 (nothing sent)"
step python3 "$CHK" apicall POST "127.0.0.1:$PORT" "$API/AdvancedSecurity/ArmWithCode" \
  'arming=stay&pID=1&ucode=1234&operation=set' - 401 -
step python3 "$CHK" apicall POST "127.0.0.1:$PORT" "$API/AdvancedSecurity/ArmWithCode" \
  'arming=stay&pID=1&operation=set' "$TOKEN" 400 'user code'
step python3 "$CHK" apicall GET "127.0.0.1:$PORT" "$API/Nope" - "$TOKEN" 404 -

say "9. the 80->301 leg preserves the path"
step python3 "$CHK" redirectget "127.0.0.1:$RPORT" "/authenticated/tuxedoapi.html?url=x"

wait "$CLI" 2>/dev/null
wait "$SRV" 2>/dev/null                    # window ends -> 501
wait "$TUX" 2>/dev/null

say "10. tuxweb serve log"
sed 's/^/   /' /tmp/serve.log

say "11. oracle: the subscriber saw snapshot, then LIVE armed, then LIVE ready"
step python3 "$CHK" verify_serve "$OUT"

say "12. oracle: the fake tuxedo saw 500, arm(2,1234), disarm(3,1234), 501"
step python3 "$CHK" verify_cmds "$CMDLOG"

say "13. cleanup"
python3 "$CHK" unlink
rm -f "$QA" "$TOK" "$CMDLOG" "$OUT" /tmp/serve.log

echo
[ "$fail" = 0 ] && echo "OK push-serve" || echo "FAIL push-serve"
exit "$fail"
