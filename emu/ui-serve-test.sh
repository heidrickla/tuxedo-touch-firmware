#!/bin/bash
# Prove tuxweb's browser pages end to end on real kernel queues, no Barracuda,
# no panel (emu/ui_check.py holds the checks):
#
#   * signed out, / goes to /login; pages, assets and 404s carry the CSP;
#   * sign-in against a throwaway account store read through a fake /tuxedo
#     (the key is read out of the binary, as on the panel); three wrong
#     passwords, then even the right one waits (429), then it signs in and the
#     cookie is HttpOnly, Secure, SameSite=Strict, Path=/;
#   * the status page carries a CSRF token; arm from the page is refused
#     without it and from another origin, then arms AWAY with p2 = 0xFFFF;
#   * the pad's disarm refuses 0000 and an empty code, then disarms with 1234;
#   * the API's ArmWithCode with no ucode now arms (0xFFFF); DisarmWithCode
#     with no ucode is still 400;
#   * the live stream showed disarmed, armed, disarmed, the LCD, and the fake
#     panel's link loss, each change once;
#   * the fake tuxedo saw exactly those four commands and no zero code.
#
#   sudo bash emu/ui-serve-test.sh
#   BIN=/path/to/tuxweb TLS=1 sudo -E bash emu/ui-serve-test.sh
set -u
BIN=${BIN:-/work/tuxweb-8a/target/debug/tuxweb}
HERE=$(cd "$(dirname "$0")" && pwd)
CHK="$HERE/push_capture_check.py"
UI="$HERE/ui_check.py"
WORK=/tmp/tuxweb-ui-test
QA=$WORK/quickarmstate
TOK=$WORK/tokens.json
CMDLOG=$WORK/cmds.tsv
PORT=48090
fail=0
say() { echo; echo "=== $* ==="; }
step() { "$@" || fail=1; }

[ -x "$BIN" ] || { echo "ABORT: no tuxweb at $BIN (set BIN=...)"; exit 1; }
for f in "$CHK" "$UI"; do [ -f "$f" ] || { echo "ABORT: no $f"; exit 1; }; done
command -v openssl > /dev/null || { echo "ABORT: no openssl"; exit 1; }

say "0. fixtures: quickarmstate, a token, a fake /tuxedo and its account store"
rm -rf "$WORK"; mkdir -p "$WORK"
printf '2 0 0 0 0 0 0 0\n' > "$QA"
TOKEN=$("$BIN" --issue-token bench "$TOK" | sed -n '2p')
[ ${#TOKEN} -eq 64 ] || { echo "ABORT: could not issue a token"; exit 1; }
python3 "$UI" mkaccounts "$WORK" || { echo "ABORT: could not make the account store"; exit 1; }
"$BIN" --accounts "$WORK/tuxedo" "$WORK/accounts.enc" | sed 's/^/  /'

if [ "${TLS:-0}" = 1 ]; then
    say "0b. TLS: throwaway cert (P-256, SAN IP:127.0.0.1)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$WORK/server.key" -out "$WORK/chain.pem" -days 2 \
        -subj "/CN=tuxweb-bench" -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null \
        || { echo "ABORT: openssl could not make a cert"; exit 1; }
    export TUXWEB_CHAIN="$WORK/chain.pem" TUXWEB_KEY="$WORK/server.key" TLS_CA="$WORK/chain.pem"
fi

say "1. queues, the reactive fake /tuxedo, then tuxweb"
python3 "$CHK" mkqueues || { python3 "$CHK" unlink; exit 1; }
python3 "$CHK" serve_tux 40 "$CMDLOG" & TUX=$!
sleep 0.5
TUXWEB_TOKEN_STORE="$TOK" TUXWEB_TUXEDO="$WORK/tuxedo" TUXWEB_ACCOUNTS="$WORK/accounts.enc" \
    "$BIN" --serve 4242 "127.0.0.1:$PORT" 30 "$QA" > "$WORK/serve.log" 2>&1 & SRV=$!
sleep 2

say "2. the browser flow"
step python3 "$UI" flow "127.0.0.1:$PORT" "$TOKEN" 14

wait "$SRV" 2>/dev/null
wait "$TUX" 2>/dev/null

say "3. tuxweb serve log (the pages' lines)"
grep -E "^ui: |pages|page stream" "$WORK/serve.log" | sed 's/^/   /'
if grep -qi "password=\|$TOKEN" "$WORK/serve.log"; then
    echo "  FAIL: the log carries a credential"; fail=1
else
    echo "  PASS: no password or token in the log"
fi

say "4. oracle: the commands that reached the queue"
step python3 "$UI" verify_ui_cmds "$CMDLOG"

say "5. cleanup"
python3 "$CHK" unlink
rm -rf "$WORK"

echo
MODE=$([ "${TLS:-0}" = 1 ] && echo "over TLS" || echo "plaintext")
[ "$fail" = 0 ] && echo "OK ui-serve ($MODE)" || echo "FAIL ui-serve ($MODE)"
exit "$fail"
