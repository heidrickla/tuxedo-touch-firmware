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

# Most checks enumerate files with `git ls-files`. Outside a working tree that
# returns nothing, every loop body is skipped, and each check prints "ok"
# against an empty list -- a vacuous pass, indistinguishable from a real one.
# Caught by running these against a `git archive` export: fourteen checks
# reported ok while "fatal: not a git repository" scrolled past between them.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ABORT: not a git working tree. The file-enumerating checks would" >&2
    echo "       every one pass against an empty list. Run from a clone." >&2
    exit 2
fi
# Enumerate tracked files AND new ones that are not ignored.
#
# Plain `git ls-files` shows only what is already in the index, so a file
# created and not yet staged is invisible to every check here. That is how a
# broken script passed a full local run and was caught only by the pre-push
# hook, once `git add` had made it visible -- a clean result that meant less
# than it looked. --others --exclude-standard closes the window without
# dragging in anything .gitignore already excludes.
ls_files() { git ls-files --cached --others --exclude-standard "$@"; }

TRACKED=$(ls_files | wc -l)
if [ "$TRACKED" -lt 20 ]; then
    echo "ABORT: ls_files returned $TRACKED files, too few for this repo." >&2
    echo "       The checks would pass by enumerating nothing." >&2
    exit 2
fi

# 1. Python syntax.
check_python() {
    local bad=""
    for f in $(ls_files '*.py'); do
        python3 -c "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())" "$f" 2>/dev/null \
            || bad="$bad $f"
    done
    [ -z "$bad" ] && pass "python syntax" || fail "python syntax" "$bad"
}

# 2. Shell syntax. Panel scripts must parse under the panel's shell.
check_shell() {
    local bad=""
    for f in $(ls_files '*.sh'); do
        sh -n "$f" 2>/dev/null || bad="$bad $f"
    done
    [ -z "$bad" ] && pass "shell syntax" || fail "shell syntax" "$bad"
}

# 3. CRLF. This repo lives on a Windows host; a CR in a script the panel
#    executes breaks it in ways that are hard to see.
check_crlf() {
    local bad=""
    for f in $(ls_files '*.sh' '*.conf' '*.example' 'upload-handler/*' 'image/*'); do
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

# 5. No private keys or credentials committed. This repo is public and is
#    about to grow TLS tooling, so the two gaps in the original mattered:
#    it only read the first 200 bytes, and its regex demanded an algorithm
#    word, so it did NOT match "-----BEGIN PRIVATE KEY-----" -- the PKCS#8
#    header openssl genpkey emits by default, i.e. the likeliest way a key
#    would actually arrive.
#
#    Prose that merely mentions the header must still pass, so a hit needs
#    the armor AND a long base64 line: documentation says the words, key
#    files carry the payload.
check_secrets() {
    local bad=""
    for f in $(ls_files); do
        [ -f "$f" ] || continue
        grep -qE -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$f" 2>/dev/null || continue
        grep -qE '^[A-Za-z0-9+/]{40,}={0,2}$' "$f" 2>/dev/null && bad="$bad $f"
    done
    for f in $(ls_files '*_ed25519' '*_rsa' 'id_*' '*.pem' '*.key'                             '*.crt' '*.der' '*.p12' '*.pfx' '*.jks' '*.keystore'); do
        case "$f" in *.pub) ;; *) bad="$bad $f";; esac
    done
    [ -z "$bad" ] && pass "no private keys committed" || fail "no private keys committed" "$bad"
}

# 5b. No vendor binaries or extracted vendor web content. This repo is public
#     and describes Honeywell's firmware; it must never redistribute it. The
#     web app ZIP embedded in Barracuda extracts to 776 files, which makes an
#     accidental commit easy now that the recipe is written down.
check_vendor_blobs() {
    local bad=""
    for f in $(ls_files); do
        # Our own captures of the wire, not vendor content: recorded frames of
        # the push protocol, no vendor code and no vendor markup. The tests
        # include them with include_bytes!, so excluding them means a clean
        # checkout cannot compile its own test suite. Kept to this one
        # directory so the exemption cannot spread.
        case "$f" in tuxweb/tests/fixtures/*.bin) continue;; esac
        case "$f" in
            *.bin|*.hdr|*.img|*.jffs2|*.zip|*.so|*.so.*|*.elf|*.hex|*.ko)
                bad="$bad $f" ;;
            */Barracuda|Barracuda|tuxedo|*/vmlinux*|vmlinux*|*/supervis|supervis)
                bad="$bad $f" ;;
            webapp/*|*/webapp/*|autogen/*|*/autogen/*)
                bad="$bad $f" ;;
        esac
    done
    # jquery and the vendor's own scripts are a strong signal of extracted content
    for f in $(ls_files '*.js'); do
        case "$f" in *jquery*|*consoleRequest*|*tuxapi*) bad="$bad $f";; esac
    done
    [ -z "$bad" ] && pass "no vendor blobs committed" || fail "no vendor blobs committed" "$bad"
}

# 5c. The patch table must stay parseable and self-consistent, because both
#     apply-patches.py and verify-panel.sh read it. A malformed row silently
#     drops a patch from BOTH the image build and the live check at once.
check_patch_table() {
    local bad=""
    [ -f patches.tsv ] || { fail "patch table" "patches.tsv missing"; return; }
    local n=0
    while IFS=$'	' read -r name binary off stock patched desc; do
        case "$name" in ''|\#*) continue ;; esac
        n=$((n+1))
        case "$off" in 0x*) ;; *) bad="$bad $name(offset-not-hex)";; esac
        case "$binary" in /*) ;; *) bad="$bad $name(binary-not-absolute)";; esac
        # stock and patched must both be the same even number of hex digits
        [ ${#stock} -eq ${#patched} ] || bad="$bad $name(length-mismatch)"
        printf '%s' "$stock$patched" | grep -qE '^[0-9a-f]+$' || bad="$bad $name(not-lowercase-hex)"
        [ "$stock" = "$patched" ] && bad="$bad $name(stock-equals-patched)"
    done < patches.tsv
    [ "$n" -gt 0 ] || bad="$bad (no rows parsed)"
    [ -z "$bad" ] && pass "patch table well formed ($n sites)"                   || fail "patch table well formed" "$bad"
}

# 6. A redirect to a variable path must not gate a command whose failure
#    matters: if the redirect cannot be opened the command never runs. Cost a
#    flash attempt. Require the target to be resolved with a fallback first.
check_redirect_gate() {
    local f=upload-handler/tuxedo-upload.sh
    local bad=""
    for f in $(ls_files '*.sh' 'upload-handler/*' 'ci/*'); do
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
    for f in $(ls_files '*.sh' 'upload-handler/*'); do
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
    for f in $(ls_files '*.sh' '*.conf' '*.conf.example' 'upload-handler/*'); do
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


# 11. Symbol versions in a shipped ARM binary. v1-v7 of dropbear were linked
#     against Debian glibc 2.41, whose headers redirect select/clock_gettime to
#     time64 wrappers. Those issue ARM syscalls 403+, which arrived in Linux
#     5.1; the panel runs 2.6.31. It bound, listened, then died in select().
#     Emulation cannot catch this: qemu-user forwards to the build host kernel.
#     The panel ships glibc 2.5, so nothing above GLIBC_2.5 may be required.
check_binary_glibc() {
    local rd bad="" f v
    rd=$(command -v arm-linux-gnueabi-readelf || command -v readelf) || true
    [ -z "$rd" ] && { skip "shipped binary glibc version" "no readelf"; return; }
    for f in $(ls_files 'ssh/bin/*' 'bin/*' 2>/dev/null); do
        [ -f "$f" ] || continue
        head -c4 "$f" | grep -q ELF || continue
        v=$("$rd" -V "$f" 2>/dev/null | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
        [ -z "$v" ] && continue
        case "$v" in
            GLIBC_2.0|GLIBC_2.1|GLIBC_2.2|GLIBC_2.3|GLIBC_2.4|GLIBC_2.5) ;;
            *) bad="$bad $f=$v" ;;
        esac
    done
    [ -z "$bad" ] && pass "shipped binary glibc version"         || fail "shipped binary glibc version" "needs >GLIBC_2.5:$bad"
}

# 12. The documented build recipe must not reintroduce the time64 link. A
#     static link against a modern glibc is what broke v1-v7.
check_no_time64_recipe() {
    local bad=""
    grep -q 'disable-largefile' ssh/BUILD.md 2>/dev/null         || bad="BUILD.md recipe lost --disable-largefile"
    grep -q 'bullseye' ssh/BUILD.md 2>/dev/null         || bad="$bad; BUILD.md no longer names the 32-bit time_t build root"
    grep -q '_TIME_BITS\|time64\|__select64' ssh/BUILD.md 2>/dev/null         || bad="$bad; BUILD.md no longer records the time64 cause"
    [ -z "$bad" ] && pass "dropbear recipe targets the panel libc"         || fail "dropbear recipe targets the panel libc" "$bad"
}

# 13. The emulation harness copies qemu-arm-static into the image root. It is
#     14 MB of build-host binary and must never reach an image.
check_no_harness_leak() {
    local bad=""
    for f in $(ls_files); do
        case "$f" in
            *qemu-arm-static*|*qemu-arm*) bad="$bad $f" ;;
        esac
    done
    [ -z "$bad" ] && pass "no emulator binary committed"         || fail "no emulator binary committed" "$bad"
}


# 14. /etc/hosts must carry no prose. /etc/rc.d/init.d/network rewrites the file
#     at boot with unanchored seds (lines 51, 58, 82, 106, 125, 144):
#         s,.*hostname,$IPADDR0     `hostname`,
#         s,.*gateway0,$GATEWAY0     gateway0,      and gateway1..gateway4
#     Any line containing those words is rewritten, comments included. The v8
#     image shipped a comment containing "hostname" and the panel turned it into
#     the live entry "203.0.113.5     6285. It asks an". Only the five real
#     gateway entries may contain a trigger word.
check_hosts_sed_triggers() {
    local f=image/etc/hosts bad=""
    [ -f "$f" ] || { skip "hosts file sed triggers" "no image/etc/hosts"; return; }
    while IFS= read -r line; do
        case "$line" in
            \#*) case "$line" in
                    *hostname*|*gateway0*|*gateway1*|*gateway2*|*gateway3*|*gateway4*)
                        bad="$bad|$line" ;;
                 esac ;;
            *) case "$line" in
                    *hostname*) bad="$bad|$line" ;;
               esac ;;
        esac
    done < "$f"
    [ -z "$bad" ] && pass "hosts file sed triggers"         || fail "hosts file sed triggers" "network(8) will rewrite:$bad"
}

# 15. Every non-comment, non-blank line of the shipped /etc/hosts must be a real
#     entry: an address followed by proper DNS names. The mangled comment the
#     panel produced, "203.0.113.5     6285. It asks an", fails here because
#     "6285." ends in a dot, giving an empty final label.
check_hosts_wellformed() {
    local f=image/etc/hosts bad="" line addr rest n
    [ -f "$f" ] || { skip "hosts file well formed" "no image/etc/hosts"; return; }
    while IFS= read -r line; do
        case "$line" in \#*|"") continue ;; esac
        case "$line" in *[![:space:]]*) ;; *) continue ;; esac
        addr=$(printf '%s
' "$line" | awk '{print $1}')
        rest=$(printf '%s
' "$line" | awk '{$1=""; print}')
        printf '%s
' "$addr" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$'             || { bad="$bad|bad address: $line"; continue; }
        [ -z "$(printf '%s' "$rest" | tr -d '[:space:]')" ]             && { bad="$bad|no name: $line"; continue; }
        for n in $rest; do
            printf '%s
' "$n"               | grep -qE '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$'               || bad="$bad|bad name '$n' in: $line"
        done
    done < "$f"
    [ -z "$bad" ] && pass "hosts file well formed" || fail "hosts file well formed" "$bad"
}

echo "regression checks"
check_python
check_shell
check_crlf
check_attribution
check_secrets
check_vendor_blobs
check_patch_table
check_redirect_gate
check_status_after_or_true
check_dropbear_flags
check_hdr_checksum
check_docs_agree
check_binary_glibc
check_no_time64_recipe
check_no_harness_leak
check_hosts_sed_triggers
check_hosts_wellformed

echo
[ "$FAIL" = "0" ] && echo "all checks passed" || echo "FAILURES PRESENT"
exit "$FAIL"
