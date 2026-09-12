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
#   TLS=1 sudo -E bash emu/push-serve-test.sh     # the whole flow over rustls,
#                                                 # chain VERIFIED by the client
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

# TLS=1: a throwaway self-signed cert with an IP SAN, served by rustls and
# VERIFIED by every client below (chain + IP match). Plaintext otherwise.
TLSDIR=/tmp/tls-test
if [ "${TLS:-0}" = 1 ]; then
    say "1b. TLS: throwaway cert (P-256, SAN IP:127.0.0.1)"
    rm -rf "$TLSDIR"; mkdir -p "$TLSDIR"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$TLSDIR/server.key" -out "$TLSDIR/chain.pem" -days 2 \
        -subj "/CN=tuxweb-bench" -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null \
        || { echo "ABORT: openssl could not make a cert"; exit 1; }
    export TUXWEB_CHAIN="$TLSDIR/chain.pem" TUXWEB_KEY="$TLSDIR/server.key"
    export TLS_CA="$TLSDIR/chain.pem"
    echo "  $(openssl x509 -in "$TLSDIR/chain.pem" -noout -subject -ext subjectAltName | tr '\n' ' ')"
fi

say "2. reactive fake /tuxedo, then tuxweb"
python3 "$CHK" serve_tux 40 "$CMDLOG" & TUX=$!
sleep 0.5
CONF=/tmp/tuxweb-serve-test.conf
CTR=/tmp/tuxweb-launches-test
if [ "${VIA_CONF:-0}" = 1 ]; then
    # Stage 8d's real launch path: the binary is named Barracuda, gets NO
    # arguments (supervis passes none), and finds the serve conf on "mtd17".
    echo "   launching as Barracuda with no arguments, switched by a serve conf"
    cp "$BIN" /tmp/Barracuda
    {
        echo "# bench serve conf"
        echo "bind=127.0.0.1:$PORT"
        echo "redirect_bind=127.0.0.1:$RPORT"
        echo "token_store=$TOK"
        echo "quickarm=$QA"
        echo "session=4242"
        [ "${TLS:-0}" = 1 ] && { echo "chain=$TUXWEB_CHAIN"; echo "key=$TUXWEB_KEY"; }
    } > "$CONF"
    say "2a. the per-boot guard: past the bound it must NOT serve"
    echo 6 > "$CTR"     # already at the limit; this launch makes 7
    TUXWEB_SERVE_CONF="$CONF" TUXWEB_LAUNCH_COUNTER="$CTR" TUXWEB_EXEC=/nonexistent \
        /tmp/Barracuda > /tmp/guard.log 2>&1; grc=$?
    if grep -q "passing through to the vendor" /tmp/guard.log && [ "$(cat "$CTR")" = 7 ]; then
        echo "  PASS: launch 7 refused serve mode and tried to pass through (exit $grc)"
    else
        echo "  FAIL: guard did not trip"; sed 's/^/     /' /tmp/guard.log; fail=1
    fi
    rm -f "$CTR"
    TUXWEB_SERVE_CONF="$CONF" TUXWEB_LAUNCH_COUNTER="$CTR" \
        /tmp/Barracuda > /tmp/serve.log 2>&1 & SRV=$!
else
    TUXWEB_TOKEN_STORE="$TOK" TUXWEB_REDIRECT_BIND="127.0.0.1:$RPORT" \
      "$BIN" --serve 4242 "127.0.0.1:$PORT" 24 "$QA" > /tmp/serve.log 2>&1 & SRV=$!
fi
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
if [ "${VIA_CONF:-0}" = 1 ]; then
    # a permanent server has no window: stop it the way the panel would
    kill -9 "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
    sleep 1; kill "$TUX" 2>/dev/null; wait "$TUX" 2>/dev/null
    PERM=permanent
else
    wait "$SRV" 2>/dev/null                # window ends -> 501
    wait "$TUX" 2>/dev/null
    PERM=
fi

say "10. tuxweb serve log"
sed 's/^/   /' /tmp/serve.log
if [ "${VIA_CONF:-0}" = 1 ]; then
    [ "$(cat "$CTR" 2>/dev/null)" = 1 ] && echo "  PASS: launch counter read 1 after the real launch" \
        || { echo "  FAIL: launch counter is '$(cat "$CTR" 2>/dev/null)', expected 1"; fail=1; }
fi

say "11. oracle: the subscriber saw snapshot, then LIVE armed, then LIVE ready"
step python3 "$CHK" verify_serve "$OUT"

say "12. oracle: the fake tuxedo saw 500, arm(2,1234), disarm(3,1234)${PERM:+ and no 501}"
step python3 "$CHK" verify_cmds "$CMDLOG" $PERM

say "13. cleanup"
python3 "$CHK" unlink
rm -f "$QA" "$TOK" "$CMDLOG" "$OUT" /tmp/serve.log /tmp/guard.log "$CONF" "$CTR" /tmp/Barracuda
rm -rf "$TLSDIR"

echo
MODE=$([ "${TLS:-0}" = 1 ] && echo "over TLS" || echo "plaintext")
[ "${VIA_CONF:-0}" = 1 ] && MODE="$MODE, launched as Barracuda via serve conf"
[ "$fail" = 0 ] && echo "OK push-serve ($MODE)" || echo "FAIL push-serve ($MODE)"
exit "$fail"
