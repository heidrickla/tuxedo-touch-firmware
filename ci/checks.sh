#!/usr/bin/env bash
# Regression checks for this repo. Each check corresponds to a failure that
# actually happened. Run from the repo root.
#
#   ci/checks.sh          all checks
#   ci/checks.sh --list   names only
set -uo pipefail
cd "$(dirname "$0")/.."

FAIL=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; FAIL=1; }
skip() { printf '  skip %s (%s)\n' "$1" "$2"; }

if [ "${1:-}" = "--list" ]; then
    grep -oP '^check_\w+' "$0" | sort -u
    exit 0
fi

# 1. Python syntax.
check_python() {
    local bad=""
    for f in $(git ls-files '*.py'); do
        python3 -c "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())" "$f" 2>/dev/null \
            || bad="$bad $f"
    done
    [ -z "$bad" ] && pass "python syntax" || fail "python syntax" "$bad"
}

# 2. Shell syntax. Panel scripts must parse under the panel's shell.
check_shell() {
    local bad=""
    for f in $(git ls-files '*.sh'); do
        sh -n "$f" 2>/dev/null || bad="$bad $f"
    done
    [ -z "$bad" ] && pass "shell syntax" || fail "shell syntax" "$bad"
}

# 3. CRLF. This repo lives on a Windows host; a CR in a script the panel
#    executes breaks it in ways that are hard to see.
check_crlf() {
    local bad=""
    for f in $(git ls-files '*.sh' '*.conf' '*.example' 'upload-handler/*'); do
        [ -f "$f" ] || continue
        grep -qU $'\r' "$f" && bad="$bad $f"
    done
    [ -z "$bad" ] && pass "no CRLF in scripts" || fail "no CRLF in scripts" "$bad"
}

# 4. No Claude attribution anywhere in history. Enforced repo-wide by the
#    owner; the harness adds it unless suppressed. git log --all is not
#    sufficient on its own: trailers survive in refs/original/ left by
#    filter-branch and in backup branches, so check every ref.
check_attribution() {
    local n
    n=$(git log --all --format='%B%an%ae' 2>/dev/null | grep -ci -e 'co-authored-by' -e 'generated with claude' -e 'noreply@anthropic' || true)
    local refs=""
    for r in $(git for-each-ref --format='%(refname)'); do
        case "$r" in refs/original/*|*backup*) refs="$refs $r";; esac
    done
    if [ "$n" != "0" ]; then
        fail "no Claude attribution in history" "$n commit(s) carry a trailer"
    elif [ -n "$refs" ]; then
        fail "no Claude attribution in history" "stale refs may hide trailers:$refs"
    else
        pass "no Claude attribution in history"
    fi
}

# 5. No private keys or credentials committed.
check_secrets() {
    local bad=""
    for f in $(git ls-files); do
        [ -f "$f" ] || continue
        head -c 200 "$f" 2>/dev/null | grep -qE 'BEGIN (OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY' && bad="$bad $f"
    done
    for f in $(git ls-files '*_ed25519' '*_rsa' 'id_*' '*.pem' '*.key'); do
        case "$f" in *.pub) ;; *) bad="$bad $f";; esac
    done
    [ -z "$bad" ] && pass "no private keys committed" || fail "no private keys committed" "$bad"
}

# 6. A redirect to a variable path must not gate a command whose failure
#    matters: if the redirect cannot be opened the command never runs. Cost a
#    flash attempt. Require the target to be resolved with a fallback first.
check_redirect_gate() {
    local f=upload-handler/tuxedo-upload.sh
    local bad=""
    for f in $(git ls-files '*.sh' 'upload-handler/*' 'ci/*'); do
        [ -f "$f" ] || continue
        if grep -qE '^[^#]*\$\{?[A-Z_]+\}? *2?>&?>?[>&]* *\$[A-Z_]+' "$f" 2>/dev/null; then
            grep -q ': >> \$' "$f" || bad="$bad $f"
        fi
    done
    [ -z "$bad" ] && pass "no unguarded log-redirect gating" || fail "no unguarded log-redirect gating" "$bad"
}

# 7. `$?` after `cmd || true` is the status of true, never of cmd. Made the one
#    line meant to report success always report success.
check_status_after_or_true() {
    local bad=""
    for f in $(git ls-files '*.sh' 'upload-handler/*'); do
        [ -f "$f" ] || continue
        awk '/\|\| *true *$/ {prev=NR} /\$\?/ {if (NR==prev+1) print FILENAME": "NR}' "$f" | grep -q . && bad="$bad $f"
    done
    [ -z "$bad" ] && pass "no \$? read after || true" || fail "no \$? read after || true" "$bad"
}

# 8. Dropbear flags that do not exist in a password-auth-disabled build.
#    -s, -g and -w are removed by DROPBEAR_SVR_PASSWORD_AUTH 0; passing them
#    makes dropbear refuse to start.
check_dropbear_flags() {
    local bad=""
    # Only files that would be deployed. Documentation quotes the bad flags
    # while explaining why they are wrong.
    for f in $(git ls-files '*.sh' '*.conf' '*.conf.example' 'upload-handler/*'); do
        [ -f "$f" ] || continue
        case "$f" in *.md) continue;; esac
        grep -qE 'DROPBEAR_ARGS=.*-[sgw]([ "]|$)' "$f" 2>/dev/null && bad="$bad $f"
    done
    [ -z "$bad" ] && pass "no removed dropbear flags in DROPBEAR_ARGS" \
        || fail "no removed dropbear flags in DROPBEAR_ARGS" "$bad"
}

# 9. Header checksum algorithm, against a hand-computed fixture and the vendor
#    values when the images are present.
check_hdr_checksum() {
    python3 ci/test_hdr.py 2>&1 | sed 's/^/       /' | grep -q FAIL \
        && fail "header checksum" "see ci/test_hdr.py output" \
        || pass "header checksum"
}

# 10. Documented addresses stay consistent with the tools.
check_docs_agree() {
    local bad=""
    grep -q '0x80003864' ssh/BUILD.md TUXEDO-BUILD.md 2>/dev/null || bad="checksum routine address missing from docs"
    grep -q 'cfg_services' ssh/BUILD.md 2>/dev/null || bad="$bad; cfg_services finding missing"
    [ -z "$bad" ] && pass "docs record the key addresses" || fail "docs record the key addresses" "$bad"
}

echo "regression checks"
check_python
check_shell
check_crlf
check_attribution
check_secrets
check_redirect_gate
check_status_after_or_true
check_dropbear_flags
check_hdr_checksum
check_docs_agree

echo
[ "$FAIL" = "0" ] && echo "all checks passed" || echo "FAILURES PRESENT"
exit "$FAIL"
