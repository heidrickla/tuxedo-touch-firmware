# Checks

`ci/checks.sh` runs every regression check. Each one corresponds to a failure
that happened in this project.

    ci/checks.sh            run all
    ci/checks.sh --list     names only
    ci/install-hooks.sh     install as a pre-push hook

`.gitea/workflows/ci.yml` runs the same script on push. If no Actions runner is
registered, use the hook.

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
