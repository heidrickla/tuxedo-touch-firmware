#!/usr/bin/env python3
"""Scan every blob in a branch's HISTORY for identifier classes.

`pubscan.py` scans the working tree and untracked files, which is the right check
before a commit. It cannot see what an OLD commit still holds, and that gap cost two
history rewrites on 2026-09-08: the panel's real address in leakfix/panelverify.sh,
and a device registration key fragment in leakfix/README.md that every working-tree
sweep had passed because the current file no longer carried it.

So this walks every blob reachable from one ref and reports what it finds. Run it
before publishing a repo, and after any history rewrite.

    python ci/histscan.py .              # scan HEAD
    python ci/histscan.py . main         # scan a named ref

🚨 SCOPED TO ONE REF ON PURPOSE, AND `--all` WOULD LIE. A background `git fetch`
re-creates refs/remotes/* from the remote, which after a local rewrite still holds
the UN-scrubbed history. With `--all` this reports the old secret as still present,
so a check that passed minutes ago starts failing on its own and the rewrite looks
broken when it is not. Deleting the tracking ref only helps until the next
auto-fetch. Scope to the branch; re-run after the push.

⚠ A clean result is not a promise the repo is safe to publish, only that these
patterns did not match. Same caveat pubscan prints, for the same reason.
"""
import collections
import re
import subprocess
import sys

# Classes worth knowing about in history. Values that identify the AUTHOR
# specifically belong in pubscan.local, not here -- this file is published, so
# putting a real prefix in it would be the exact failure it exists to prevent.
PATTERNS = {
    "private IPv4 (10/8)": rb"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "private IPv4 (192.168)": rb"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    "private IPv4 (172.16-31)": rb"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
    "MAC address": rb"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
    "private key armor": rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "email address": rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "AWS-style key id": rb"\bAKIA[0-9A-Z]{16}\b",
    # Mirrors pubscan's "raw hex key material": credential CONTEXT beside the hex,
    # never a bare long-hex test. This repo is full of Barracuda md5sums and 40-char
    # git SHAs, and a bare test reports hundreds of lines -- which teaches you to
    # skim the category on the day it finds a real key.
    "raw hex key material":
        rb"(?i)\b(?:priv(?:ate)?key|pub(?:lic)?key|authtoken|token|secret|apikey)"
        rb"['\"]?\s*[:=]\s*['\"]?[0-9a-f]{16,}",
    "credential assignment":
        rb"(?i)\b(?:passwd|password)\s*[:=]\s*['\"][^'\"]{8,}",
    "Windows user path": rb"[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9._-]+",
}

# Documentation ranges (RFC 5737, RFC 3849), network addresses, and the vendor's own
# published contact. Reporting these is how a real hit gets skimmed past.
ALLOW = re.compile(
    rb"203\.0\.113\.|192\.0\.2\.|198\.51\.100\.|"
    rb"\b(?:10|192\.168)\.\d{1,3}\.\d{1,3}\.0\b|"      # network addresses
    rb"example\.(?:com|org|net)|\.invalid\b|\.notreal\b|notreal\.tld|"
    rb"noreply@|realtimelogic\.com|"
    rb"@[0-9]x\.(?:png|jpe?g|svg|gif|webp)|"           # logo@2x.png is not an email
    rb"deadbeef|0123456789abcdef",
    re.IGNORECASE,
)
# ⚠ NO MAC LITERALS IN THIS FILE, not even placeholders, and not in a comment
# either. A first version listed the two obvious sequential/repeated placeholders
# here to cut noise; pubscan immediately flagged this file for "real MAC addresses",
# because its placeholder filter recognises all-zero, all-ff, and the
# locally-administered bit — not an ascending one. Rewriting the warning then put the
# same two literals back inside the comment explaining not to write them, and it
# fired again. pubscan.py's own notes record this happening five times in one day.
# MAC-shaped hits are left to triage instead: the tool reports, it does not judge.


def git(repo, args):
    return subprocess.run(["git", "-C", repo] + args, capture_output=True)


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    ref = sys.argv[2] if len(sys.argv) > 2 else "HEAD"

    if git(repo, ["rev-parse", "--git-dir"]).returncode:
        sys.exit("not a git repository: %s" % repo)
    if git(repo, ["rev-parse", "--verify", ref]).returncode:
        sys.exit("no such ref: %s" % ref)

    named = {}
    for line in git(repo, ["rev-list", "--objects", ref]).stdout.decode(
            "utf-8", "replace").splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1]:
            named.setdefault(parts[0], parts[1])

    blobs = set()
    for line in git(repo, ["cat-file", "--batch-check", "--batch-all-objects"]
                    ).stdout.decode("utf-8", "replace").splitlines():
        f = line.split()
        if len(f) >= 2 and f[1] == "blob":
            blobs.add(f[0])

    targets = sorted(o for o in named if o in blobs)
    if not targets:
        # An empty target list would print a clean summary while checking nothing,
        # which is the failure mode this repo has hit more than once.
        sys.exit("REFUSING: no blobs found for %s -- scanning nothing would "
                 "report clean" % ref)
    print("scanning %d blob(s) reachable from %s" % (len(targets), ref))

    compiled = {k: re.compile(v) for k, v in PATTERNS.items()}
    hits = collections.defaultdict(set)
    for o in targets:
        data = git(repo, ["cat-file", "blob", o]).stdout
        if b"\0" in data[:8192]:
            continue
        for label, rx in compiled.items():
            for m in rx.findall(data):
                s = m if isinstance(m, bytes) else m[0]
                if ALLOW.search(s):
                    continue
                hits[label].add((s.decode("utf-8", "replace")[:60], named[o]))

    print()
    if not hits:
        print("No matches outside the allowlist. That is not a promise the history")
        print("is safe to publish, only that these patterns did not match.")
        return 0
    total = sum(len(v) for v in hits.values())
    for label in sorted(hits):
        print("%s: %d distinct" % (label, len(hits[label])))
        for val, path in sorted(hits[label])[:12]:
            print("    %-44s %s" % (val, path))
        if len(hits[label]) > 12:
            print("    ... and %d more" % (len(hits[label]) - 12))
    print()
    print("%d distinct value(s) across %d class(es). Triage each one: a hit is not"
          % (total, len(hits)))
    print("automatically a leak, and a vendor constant is not your identity.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
