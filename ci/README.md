# Checks

`ci/checks.sh` runs every regression check. Each one corresponds to a failure
that happened in this project.

    ci/checks.sh            run all
    ci/checks.sh --list     names only
    ci/install-hooks.sh     install as a pre-push hook

`.gitea/workflows/ci.yml` runs the same script on push. **No Actions runner is
currently registered** (Gitea 1.24.7 supports them; none found on this host), so
on that remote the pre-push hook is the working path until one is added.

`.github/workflows/ci.yml` does run, on GitHub's own runners, and is green. It
adds a second job for `tuxweb`: `cargo test`, a release build, a cross-build for
`arm-unknown-linux-musleabi`, and an assertion that the result really is a
static ARM binary. The cross-build is in CI rather than only in `BUILD.md`
because it has its own failure mode — `ring` needs a C cross-compiler and
`cc-rs` looks for one Ubuntu does not ship — and an unrun recipe is a guess.

## `ci/dryrun.sh` — run CI without pushing

Clones a bundle of `HEAD` and runs every workflow step against it. Two bugs came
out of writing it, and neither was visible from the working tree:

- **The repo could not build itself.** `*.bin` in `.gitignore` excluded
  `tuxweb/tests/fixtures/`, which the frame tests pull in with `include_bytes!`.
  Locally the files exist, so `cargo test` passed; from a clean checkout it
  would not compile.
- **`checks.sh` passed vacuously outside a working tree.** Most checks enumerate
  with `git ls-files`, which returns nothing there, so fourteen of them reported
  `ok` against an empty list while `fatal: not a git repository` scrolled past
  between the lines. It aborts now, and `dryrun.sh` asserts that it does.

The first version of `dryrun.sh` used `git archive`, which is exactly what hid
the second bug. It uses a real clone.

| Check | Failure it prevents |
|---|---|
| python syntax | broken tool committed |
| shell syntax | panel script that will not parse |
| no CRLF in scripts | repo is on a Windows host; a CR breaks panel scripts invisibly |
| no Claude attribution | owner rule; `git log --all` misses `refs/original/` and backup branches, so refs are checked too |
| no private keys | `tuxedo_ed25519` sits next to the repo |
| no unguarded log-redirect gating | `cmd >> $LOG \|\| true` never runs `cmd` if `$LOG` is unwritable; cost a flash |
| no `$?` after `\|\| true` | reports the status of `true`, so the line meant to report failure always reported success |
| no removed dropbear flags | `-s -g -w` do not exist with `DROPBEAR_SVR_PASSWORD_AUTH 0`; dropbear refuses to start |
| header checksum | a 16-bit end-around-carry accumulator matches short inputs and diverges on long ones; cost a flash |
| docs record key addresses | keeps `0x80003864` and the `cfg_services` finding from being dropped |

`pubscan.py` is deliberately **not** in that table: it needs the untracked
`pubscan.local` to say anything useful, so it is a pre-publish step you run, not a
gate `checks.sh` can enforce. See below.

## `ci/pubscan.py` — author identifiers before publishing

Scans for anything identifying the author or the house network: real MACs, local
paths, SSIDs, keys, tokens, personal email, hostnames, house addresses, the panel
MAC. Patterns live in the untracked `ci/pubscan.local`, so the list itself is not
published.

**It scans untracked-but-unignored files as well as tracked ones.** `git ls-files`
alone cannot see a file you have not added yet, and 22 untracked files carrying a
real MAC were the entire exposure in a sibling repo. Running it before or after
`git add` gives the same answer.

It did not always do that, and the gap cost a history rewrite. On 2026-09-08 the
panel's real address shipped in `leakfix/panelverify.sh` because the file was
untracked when the scan ran; **history was rewritten the same day to replace the two
real addresses with documentation-range ones** (`git filter-repo --replace-text`,
three lines in one file in one commit, 313 commits before and after, tip tree
byte-identical). Every hash from that commit forward changed, so an older clone
cannot fast-forward — re-clone or reset to the remote.

## `ci/histscan.py` — the same question, asked of HISTORY

`pubscan.py` checks the working tree and untracked files. It cannot see what an old
commit still holds, and that gap cost both rewrites on 2026-09-08 — the second
because a key fragment sat in a file whose *current* version no longer carried it,
so every working-tree sweep passed.

    python ci/histscan.py .              # scan HEAD
    python ci/histscan.py . main         # a named ref

Run it before publishing, and again after any rewrite. It triages nothing: a hit is
not automatically a leak, and the output says so. The standing hits on this repo were
all checked and are all benign: pubscan's own `10.77` self-test fixtures,
`10.0.0.0`/`192.168.0.0` as network addresses in docs, `image/etc/hosts` gateway
placeholders, the private-key armor string inside `checks.sh`'s own pattern, the
vendor's published `ginfo@realtimelogic.com`.

**It scans ONE ref, and `--all` would lie.** A background `git fetch` re-creates
`refs/remotes/*` from the remote, which after a local rewrite still holds the
un-scrubbed history: `--all` then reports the old secret as present, and a check
that passed minutes ago starts failing on its own. Deleting the tracking ref only
helps until the next auto-fetch.

**Masking a value forward does not remove it from history.** `histscan` keeps
reporting the old blob, correctly: it still lists the truncated registration-key
fragment because the current file is masked and the historical one is not. Removing
it needs another rewrite; for a non-exploitable prefix, rotating the credential is
the better fix.

## Vendor image tests

`ci/test_hdr.py` verifies the checksum against hand-computed fixtures always,
and against the five vendor `.hdr` files when they are available:

    TUXEDO_FW_DIR=/path/to/fw python3 ci/test_hdr.py

The images are not committed.
