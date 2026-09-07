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

## Vendor image tests

`ci/test_hdr.py` verifies the checksum against hand-computed fixtures always,
and against the five vendor `.hdr` files when they are available:

    TUXEDO_FW_DIR=/path/to/fw python3 ci/test_hdr.py

The images are not committed.
