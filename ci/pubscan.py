#!/usr/bin/env python3
"""What would publishing this repo disclose? Run it BEFORE making one public.

This repo went public on 2026-09-07 without this step, and the sibling repos
that did get one (`ha-sleepiq`, `ha-glkvm`, `ha-att-router-reboot`, `crossword`)
each had a dedicated "security scan before publishing" pass. The difference was
that somebody remembered, four times, and then did not a fifth. A tool that runs
in ten seconds is a better guarantee than that.

⚠ IT IS A REPORT, NOT A GATE, and deliberately exits 0 with findings. Whether
the panel's own IP belongs in a firmware write-up is a judgement call the owner
makes -- wiring it into `checks.sh` would either fail the build for a decision
already taken, or get an exception that makes it decorative. It prints; a person
decides.

WHY THE HOUSE SECRET SCANNER IS NOT ENOUGH, stated because it reported clean on
this repo while every item below was present: `brain/scripts/scan-secrets.py`
matches CREDENTIAL SHAPES -- AWS keys, tokens, PEM blocks. It cannot know that a
particular four-digit number is an alarm code or that a hostname is the author's.
"scan-secrets: clean" answers a narrower question than "is this safe to publish",
and reading it as the second is how the third-party detail below survived.

NEVER PRINTS A SECRET. Counts, filenames and categories only, so the output of a
scan for exposure does not become the exposure.

VENDOR CONTENT IS NOT DISCLOSURE. The panel ships an /etc/hosts full of
192.168.0.x; reproducing it discloses nothing about the person publishing. Those
are separated out rather than inflating the count -- a scanner that cries about
the vendor's own defaults gets ignored on the day it finds something real.

    python ci/pubscan.py [--repo PATH]
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

#: Files that contain detector patterns BY CONSTRUCTION -- a scanner matching
#: its own regexes is not a finding. Named rather than pattern-matched, so
#: adding a file here is a visible decision and cannot quietly hide a real one.
SELF = {"ci/checks.sh", "ci/pubscan.py"}

#: MACs that are placeholders, not anybody's hardware: the null address, the
#: broadcast address, and locally-administered ones (bit 1 of the first octet),
#: which is what an emulator hands out -- `02:00:00:00:00:01` here.
#: ⚠ THE FIRST VERSION COUNTED THESE and reported "4 MACs in 3 files" when the
#: repo holds exactly one real MAC. Over-reporting is not the safe direction:
#: this file's own docstring says a scanner that cries about placeholders gets
#: skimmed on the day it finds something, and it did that on its first run.
#: `00:d0:2d:00:00:01` joins them: it is what the real MAC was replaced WITH
#: when this repo's history was genericised. The Resideo OUI is kept because
#: the integration's DHCP discovery matches on it and the docs explain that,
#: but the host part is zeroed, so it is an example and not a device.
_PLACEHOLDER_MAC = re.compile(
    r"^(?:00:00:00:00:00:00|ff:ff:ff:ff:ff:ff|00:d0:2d:00:00:01"
    r"|[0-9a-f][26ae]:)", re.I)


def real_macs(text: str) -> list[str]:
    return [m for m in re.findall(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", text, re.I)
            if not _PLACEHOLDER_MAC.match(m)]


def _local_identifiers() -> list[tuple[str, "re.Pattern[str]"]]:
    """Author-specific literals, read from an untracked file beside this one.

    THE POINT: a scanner that carries "look for the string Workstation" tells
    every reader the hostname it is protecting. This file previously did
    exactly that, for a hostname and for two personal domains, and it is
    published. So the literals live in `ci/pubscan.local`, which .gitignore
    excludes, and the tracked file keeps only patterns that are structural -
    private address ranges, MAC shapes, key headers - which identify nobody.

    Format: one entry per line, `label<TAB>regex`. Blank lines and `#`
    comments ignored. Absent file means no author literals, which is the right
    behaviour for anyone who is not the author and cannot be a false clean:
    the structural detectors still run and still report.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pubscan.local")
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "\t" not in line:
                continue
            label, _, pattern = line.partition("\t")
            try:
                out.append((label.strip(), re.compile(pattern.strip(), re.I)))
            except re.error as err:
                print("pubscan: bad pattern in pubscan.local for %r: %s" % (label, err))
    return out


#: Identifiers belonging to the AUTHOR, which publication would disclose.
#: Structural only. Nothing here names a person, a host or a domain, so this
#: list can be published without disclosing what it defends. Anything that
#: WOULD name one goes in ci/pubscan.local -- see _local_identifiers.
YOURS = [
    ("private addresses, 10.10.x", re.compile(r"\b10\.10\.\d{1,3}\.\d{1,3}\b")),
    ("real MAC addresses", real_macs),
    # A Windows user directory discloses the account name whoever it is, so the
    # shape is worth reporting on its own without naming anybody.
    ("local filesystem paths", re.compile(r"[A-Za-z]:\\{1,2}(?:Users|temp|Temp)\b")),
    ("wifi ssid / psk", re.compile(r"(?i)\b(ssid|psk|wpa_passphrase)\s*[:=]\s*\S")),
    ("private keys", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("bearer tokens", re.compile(r"\b(?:ghp|gho|github_pat|xox[baprs])[-_][0-9A-Za-z_-]{16,}")),
] + _local_identifiers()

#: Present, but the VENDOR's, so publishing them discloses nothing about you.
VENDOR = [
    ("vendor default addrs", re.compile(
        r"\b(?:192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
]


def tracked(repo: str) -> list[str]:
    r = subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True,
                       text=True)
    if r.returncode:
        sys.exit("pubscan: not a git repo: %s" % repo)
    return [f for f in r.stdout.splitlines() if f.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args()

    files = tracked(args.repo)
    blobs = {}
    for f in files:
        try:
            with open(os.path.join(args.repo, f), "rb") as fh:
                blobs[f] = fh.read().decode("utf-8", "replace")
        except OSError:
            continue

    print("pubscan: %d tracked files in %s" % (len(blobs), args.repo))
    print("         (%s excluded: they hold detector patterns by construction)\n"
          % ", ".join(sorted(SELF)))
    total = 0
    for label, rx in YOURS:
        find = rx if callable(rx) else rx.findall
        hits = {}
        for f, b in blobs.items():
            if f.replace("\\", "/") in SELF:
                continue
            n = len(find(b))
            if n:
                hits[f] = n
        n = sum(hits.values())
        total += n
        print("%s %-26s %3d file(s)  %4d hit(s)"
              % ("  >>" if hits else "    ", label, len(hits), n))
        for f in sorted(hits, key=lambda k: -hits[k])[:5]:
            print("        %-50s x%d" % (f, hits[f]))
        if len(hits) > 5:
            print("        ... and %d more file(s)" % (len(hits) - 5))

    print()
    for label, rx in VENDOR:
        hits = {f: len(rx.findall(b)) for f, b in blobs.items() if rx.search(b)}
        print("    %-26s %3d file(s)  %4d hit(s)   [vendor, not yours]"
              % (label, len(hits), sum(hits.values())))

    print()
    if total:
        print("%d occurrence(s) of your own identifiers are in tracked files." % total)
        print("Publishing discloses them. Genericise, or decide deliberately")
        print("that they are fine -- but decide, do not default.")
    else:
        print("No author identifiers found. That is not a promise the content is")
        print("safe to publish, only that this list did not match.")
    return 0            # a report, never a gate. See the module docstring.


if __name__ == "__main__":
    sys.exit(main())
