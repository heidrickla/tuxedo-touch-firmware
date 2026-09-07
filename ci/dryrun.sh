#!/bin/bash
# Run the GitHub workflow's steps against a real clone of HEAD.
#
# The point is to catch what reading a workflow file cannot tell you: whether
# the repository as committed builds itself. It did not -- the test fixtures
# were gitignored -- and that was invisible from the working tree, where the
# files exist.
#
# A clone, not a `git archive` export: most checks in ci/checks.sh enumerate
# with `git ls-files`, so outside a working tree they pass against an empty
# list. That is how this script was wrong the first time.
set -u
D=/tmp/ci-dryrun
rm -rf "$D"
git clone -q /tmp/repo.bundle "$D" || exit 1
cd "$D" || exit 1

export RUSTUP_HOME=/build/rt/rustup CARGO_HOME=/build/rt/cargo
export PATH=/build/rt/cargo/bin:$PATH
export CC_arm_unknown_linux_musleabi=arm-linux-gnueabi-gcc
export AR_arm_unknown_linux_musleabi=arm-linux-gnueabi-ar

fail=0
step() { echo; echo "=== $* ==="; }

step "this is a real clone with history"
echo "  tracked files: $(git ls-files | wc -l), commits: $(git rev-list --count HEAD)"

step "the fixtures the tests compile against are present"
ls -l tuxweb/tests/fixtures/ || { echo "MISSING"; fail=1; }

step "ci/checks.sh"
bash ci/checks.sh
[ $? = 0 ] || { echo "checks.sh FAILED"; fail=1; }

step "cargo test --locked"
( cd tuxweb && cargo test --locked --all-targets 2>&1 | tail -5 ) || fail=1

step "cargo build --locked --release"
( cd tuxweb && cargo build --locked --release 2>&1 | tail -2 ) || fail=1

step "cross-build for the panel"
( cd tuxweb && cargo build --locked --release --target arm-unknown-linux-musleabi 2>&1 | tail -2 ) || fail=1

step "the shipped binary is a static ARM executable"
f=tuxweb/target/arm-unknown-linux-musleabi/release/tuxweb
if [ -f "$f" ]; then
    file "$f"
    file "$f" | grep -q ARM || { echo "not ARM"; fail=1; }
    file "$f" | grep -q "statically linked" || { echo "not static"; fail=1; }
else
    echo "no binary produced"; fail=1
fi

step "and the guard works: checks.sh must REFUSE a non-repo"
rm -rf /tmp/ci-notrepo && mkdir -p /tmp/ci-notrepo
tar -cf - --exclude=.git -C "$D" . | tar -xf - -C /tmp/ci-notrepo
if bash /tmp/ci-notrepo/ci/checks.sh >/dev/null 2>&1; then
    echo "  it PASSED outside a repo -- the vacuous-pass bug is back"; fail=1
else
    echo "  refused, exit $? -- vacuous pass is not possible"
fi

echo
if [ "$fail" = 0 ]; then echo "DRY RUN PASSED"; else echo "DRY RUN FAILED"; fi
exit "$fail"
