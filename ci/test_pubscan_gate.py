#!/usr/bin/env python3
"""Guard test for `pubscan.py --gate`, the pre-push author-identifier gate.

The gate exists because the panel's real address regressed into five tracked
files 2026-09-11..13 and nothing caught it: pubscan's report exits 0 with
findings by design, and ci/checks.sh did not run pubscan at all. This test pins
the gate's three outcomes so a later edit that softens it goes red.

Hermetic: it does NOT read the author's real ci/pubscan.local. Each case builds
a throwaway git repo, copies the pubscan.py under test into its ci/, writes a
SYNTHETIC ci/pubscan.local beside that copy (pubscan reads the file next to its
own __file__, not next to --repo), commits some files, and runs

    python <tmp>/ci/pubscan.py --gate --repo <tmp>

Exit codes asserted (from pubscan.gate): 3 findings, 0 clean, 2 no-local-skip.

Run: python3 ci/test_pubscan_gate.py   (exit 0 pass, 1 fail)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PUBSCAN = os.path.join(HERE, "pubscan.py")

# A synthetic literal that identifies nobody: a documentation-range address the
# real scrub map does NOT use, so a stray copy of this file discloses nothing.
SECRET = "10.99.88.7"
LOCAL_LINE = "test house addr\t\\b10\\.99\\.88\\.\\d{1,3}\\b\n"

FAILED = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if ok:
        print("ok   %s" % name)
    else:
        FAILED += 1
        print("FAIL %s%s" % (name, ("  " + detail) if detail else ""))


def _git(repo: str, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _make_repo(root: str, *, with_local: bool, with_secret: bool) -> None:
    """A git repo with pubscan.py (and optionally pubscan.local) under ci/."""
    ci = os.path.join(root, "ci")
    os.makedirs(ci)
    shutil.copy(PUBSCAN, os.path.join(ci, "pubscan.py"))
    if with_local:
        with open(os.path.join(ci, "pubscan.local"), "w", encoding="utf-8") as fh:
            fh.write(LOCAL_LINE)
    with open(os.path.join(root, "clean.md"), "w", encoding="utf-8") as fh:
        fh.write("A clean file. Panel at 203.0.113.5, nothing author-specific.\n")
    if with_secret:
        with open(os.path.join(root, "leak.md"), "w", encoding="utf-8") as fh:
            fh.write("Oops, the panel is at %s on the LAN.\n" % SECRET)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    # pubscan.local is gitignored in the real repo; mirror that so `git ls-files`
    # never lists it and the gate cannot flag the detector file itself.
    with open(os.path.join(root, ".gitignore"), "w", encoding="utf-8") as fh:
        fh.write("ci/pubscan.local\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "x")


def _run_gate(root: str) -> int:
    r = subprocess.run(
        [sys.executable, os.path.join(root, "ci", "pubscan.py"),
         "--gate", "--repo", root],
        capture_output=True, text=True)
    return r.returncode


def main() -> int:
    cases = 0
    # 1. A tracked file carrying the literal -> FAIL (3).
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "r")
        _make_repo(root, with_local=True, with_secret=True)
        cases += 1
        check("findings -> exit 3", _run_gate(root) == 3)

    # 2. Local patterns present, no tracked file carries one -> CLEAN (0).
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "r")
        _make_repo(root, with_local=True, with_secret=False)
        cases += 1
        check("clean -> exit 0", _run_gate(root) == 0)

    # 3. No pubscan.local (CI, fresh clone) -> SKIP (2), never a fail.
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "r")
        _make_repo(root, with_local=False, with_secret=True)
        cases += 1
        rc = _run_gate(root)
        check("no local -> exit 2 (skip, not fail)", rc == 2,
              "got %d" % rc)

    print("gate cases checked: %d" % cases)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
