# Working in this repo

**Read `TRAPS.md` first.** It is short and every entry in it is something that
already produced a confident wrong answer here.

Then: grep the repo for your topic before writing any script. The recipe
usually exists — `ssh/BUILD.md` (emulation, transfers), `TUXEDO-BUILD.md`
(images, header checksum), `WEBSERVER-REPLACEMENT.md` (IPC, queues), `emu/`
(running the ARM binaries).

- `patches.tsv` is the single source of truth and holds **file offsets**.
- `verify-panel.sh` checks the running panel; `apply-patches.py` checks a tree.
- Prove anything touching the request path under `emu/` before flashing.
- No attribution trailers in commits.
