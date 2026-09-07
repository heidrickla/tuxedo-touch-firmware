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

EXIT CODES, and the distinction matters:

    0   the scan ran. Clean, or with findings -- both, on purpose.
    2   THE SCAN COULD NOT RUN. Not a git repo, or no ci/pubscan.local so the
        author-specific detectors do not exist.

"Report, not gate" is a statement about FINDINGS, which are a judgement call.
It is not a statement about a scan that did not happen, which is not a judgement
call at all and is the one state where a human's decision is not the thing
missing. Returning 0 there would mean `pubscan && publish` passes silently on a
fresh clone, with the prose saying NOT CLEAN and the exit code saying fine --
and a script reads the second. probe/supervis_heartbeat.py already uses
0 / 1 / 2 in this repo; two tools with opposite conventions is its own trap.
There is no rc=1 here because "findings present" is deliberately not a failure.

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


#: Account names that name nobody: what a scrub replaces a real one with, plus
#: the usual CI and container accounts. Kept short and explicit — guessing at
#: "looks generic" would start hiding real names.
_GENERIC_ACCOUNT = re.compile(
    r"^(?:dev|user|users|test|admin|administrator|runner|build|ci|root|"
    r"youruser|username)$", re.I)

_USER_PATH = re.compile(r"[A-Za-z]:\\{1,2}Users\\{1,2}([A-Za-z0-9._-]+)")
_TEMP_PATH = re.compile(r"[A-Za-z]:\\{1,2}(?:temp|Temp)\b")


def _user_paths(text: str) -> tuple[list[str], list[str]]:
    """Split Windows user paths into the ones that name somebody and the rest."""
    named, generic = [], []
    for m in _USER_PATH.finditer(text):
        (generic if _GENERIC_ACCOUNT.match(m.group(1)) else named).append(m.group(0))
    return named, generic


def real_user_paths(text: str) -> list[str]:
    """Paths carrying a real account name, plus bare temp roots."""
    return _user_paths(text)[0] + _TEMP_PATH.findall(text)


def generic_user_paths(text: str) -> list[str]:
    return _user_paths(text)[1]


def _local_identifiers() -> list[tuple[str, "re.Pattern[str]"]]:
    """Author-specific literals, read from an untracked file beside this one.

    THE POINT: a scanner that carries "look for the string <hostname>" tells
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
    # The host octet may be digits OR a mask. Requiring digits let a masked
    # address survive three separate sweeps of this repo: a masked host octet
    # LOOKS scrubbed, while the /24 left beside it is the part that identifies
    # the network. Masking the host hides the least useful field.
    #
    # Writing the example out in full here is how the same string then survived
    # a FOURTH pass, in the comment explaining why it should not be present.
    # The self-check at the end of main() caught that. Do not put a real
    # address in this file, not even as an illustration.
    #
    # THE SUBNET ITSELF IS NOT IN THIS FILE. A /16 the author uses is an author
    # identifier, and a first version of this hardcoded it here -- then put it
    # in the test cases too, which is the fifth time in one day that a real
    # value ended up in the file whose job is to keep real values out. The
    # prefix lives in ci/pubscan.local as "house addresses"; this file supplies
    # the mask-aware machinery and nothing else. See masked_addr_re.
    ("real MAC addresses", real_macs),
    # A Windows user directory discloses the account NAME, so what matters is
    # the name and not the shape. `C:\Users\dev\...` after a scrub identifies
    # nobody, and reporting 23 of those in red is how the next person learns to
    # skim this category on the day it finds a real one - the same failure the
    # placeholder-MAC filter exists to prevent. Generic account names are split
    # off to an informational line below rather than counted here.
    ("local filesystem paths", real_user_paths),
    ("wifi ssid / psk", re.compile(r"(?i)\b(ssid|psk|wpa_passphrase)\s*[:=]\s*\S")),
    ("private keys", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("bearer tokens", re.compile(r"\b(?:ghp|gho|github_pat|xox[baprs])[-_][0-9A-Za-z_-]{16,}")),
] + _local_identifiers()

def masked_addr_re(prefix: str) -> "re.Pattern[str]":
    """Match `<prefix>.<octet>.<host>` where the host may be digits OR a mask.

    Requiring digits in the host octet let a masked address survive three
    separate sweeps of this repo. A masked host LOOKS scrubbed while the
    network part beside it is the half that identifies anything; masking the
    host hides the least useful field.

    `\\*` sits OUTSIDE the character class and the tail is `(?!\\w)` rather than
    `\\b`, and both are load-bearing. `\\b` after `*` -- a non-word character --
    asserts that a WORD character follows, so a `.*` form can never match in any
    context. The first version listed `*` inside the class and therefore claimed
    four mask forms while catching three: the alternative LOOKED covered because
    the character was sitting right there, which is the same shape as the bug
    this pattern exists to find.

    `prefix` is a regex fragment such as `10\\.10`, supplied by the caller.
    Real prefixes belong in ci/pubscan.local, never here.
    """
    return re.compile(r"\b" + prefix + r"\.\d{1,3}\.(?:\d{1,3}|[xXn]+|\*)(?!\w)")


#: Cases for masked_addr_re, run by `--selftest`, against a SYNTHETIC prefix.
#:
#: A detector with no case that makes it FIRE is the failure this repo has been
#: chasing all day, and this one shipped with a dead branch. The negative cases
#: matter as much: `[xXn]+` could plausibly swallow an ordinary word after a
#: dotted quad, and `.next` proves it does not.
SELFTEST_PREFIX = r"10\.77"
MASK_CASES = (
    ("10.77.52.5", True), ("10.77.52.x", True), ("10.77.52.X", True),
    ("10.77.52.n", True), ("10.77.52.xxx", True),
    ("10.77.52.*", True), ("10.77.52.* end", True), ("addr 10.77.52.*", True),
    ("10.77.52.*)", True), ("panel at 10.77.54.x on the vlan", True),
    ("10.77.52.next", False), ("10.77.52.name", False), ("10.77.52.node1", False),
    ("192.168.1.x", False), ("10.20.30.x", False), ("203.0.113.x", False),
    ("110.77.52.5", False), ("10.100.52.5", False),
)


def selftest() -> int:
    """Prove masked_addr_re fires and refuses on the right inputs."""
    rx = masked_addr_re(SELFTEST_PREFIX)
    bad = 0
    for text, want in MASK_CASES:
        got = bool(rx.search(text))
        if got != want:
            bad += 1
            print("  FAIL %-34r want %s got %s" % (text, want, got))
    print("  %d case(s), %d failure(s)" % (len(MASK_CASES), bad))
    if not any(w for _, w in MASK_CASES):
        print("  ABORT: no case expects a match; this test cannot fail")
        return 2
    return 1 if bad else 0


#: Present, but discloses nothing about you: the vendor's own defaults, and
#: paths whose account name is a placeholder. Reported so the count is honest
#: about what it excluded, never added to the total.
VENDOR = [
    ("vendor default addrs", re.compile(
        r"\b(?:192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
    ("local paths, generic account", generic_user_paths),
]


def untracked(repo: str) -> list[str]:
    """Files that are neither tracked nor ignored.

    These are invisible to `git ls-files` and were the entire exposure in a
    sibling repo: 22 untracked, unignored files carrying a real MAC, house
    addresses and author paths, in a repo that is public. Scanning only tracked
    files would have called it clean.

    They are reported in their own bucket rather than folded into the total,
    because they are not published YET -- but they are one `git add -A` from
    being exactly that, which is the state this tool is meant to be run before.
    """
    r = subprocess.run(["git", "ls-files", "--others", "--exclude-standard"],
                       cwd=repo, capture_output=True, text=True)
    return [f for f in r.stdout.splitlines() if f.strip()] if not r.returncode else []


def tracked(repo: str) -> list[str]:
    r = subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True,
                       text=True)
    if r.returncode:
        print("pubscan: not a git repo: %s" % repo)
        print("  Nothing was scanned. This is NOT a clean result.")
        raise SystemExit(2)          # could not evaluate, never 0 or 1
    return [f for f in r.stdout.splitlines() if f.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--selftest", action="store_true",
                    help="check the private-address pattern against MASK_CASES")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    files = tracked(args.repo)
    blobs = {}
    for f in files:
        try:
            with open(os.path.join(args.repo, f), "rb") as fh:
                blobs[f] = fh.read().decode("utf-8", "replace")
        except OSError:
            continue

    print("pubscan: %d tracked files in %s" % (len(blobs), args.repo))
    print("         (%s excluded: they hold detector patterns by construction)"
          % ", ".join(sorted(SELF)))

    # SAY HOW MANY AUTHOR DETECTORS ARE LOADED, AS A NUMBER.
    #
    # The author-specific patterns live in ci/pubscan.local, which .gitignore
    # excludes -- so a FRESH CLONE HAS NONE OF THEM. Eight of the fourteen
    # categories simply vanish, silently, and the closing line was byte
    # identical either way. The eight that vanish are the ones that caught every
    # leak found on 2026-09-07: the author hostname in this file's own
    # docstring, the monitoring host's DNS name, and the author paths in a
    # sibling repo. The six structural detectors that survive would have caught
    # none of them.
    #
    # The old docstring reasoned that an absent file "cannot be a false clean".
    # That is true for a stranger, who has no author literals to find. It is
    # FALSE for the author on a fresh clone -- and re-cloning is the state this
    # repo was just told to expect. Right for the reader it imagined, wrong for
    # the one it gets. So: print the count, and never claim "no author
    # identifiers found" from a run that could not look for them.
    n_local = len(_local_identifiers())
    if n_local:
        print("         author literals loaded: %d from ci/pubscan.local" % n_local)
    else:
        print("         author literals loaded: 0 -- ci/pubscan.local ABSENT.")
        print("         THE AUTHOR-SPECIFIC DETECTORS DID NOT RUN. This scan")
        print("         checked structure only; it cannot see a hostname, a")
        print("         domain, a subnet or a local path. --selftest still")
        print("         passes because it tests the pattern SHAPE against a")
        print("         synthetic prefix, not whether a real one is loaded.")
    print()
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
        find = rx if callable(rx) else rx.findall
        hits = {}
        for f, b in blobs.items():
            if f.replace("\\", "/") in SELF:
                continue
            n = len(find(b))
            if n:
                hits[f] = n
        print("    %-26s %3d file(s)  %4d hit(s)   [discloses nothing]"
              % (label, len(hits), sum(hits.values())))

    # The SELF files are skipped above because they carry detector patterns by
    # construction -- 10\.10\.\d+ would match its own regex. That exclusion is
    # right for patterns and WRONG for prose, and it hid a real leak: this
    # file's own docstring named the author's hostname while explaining why the
    # hostname should not be in this file. Published, and invisible to the tool
    # by design. So the SELF files are checked explicitly against the private
    # identifier list, which is the one thing they must never contain.
    leaked = {}
    for label, rx in _local_identifiers():
        for f in sorted(SELF):
            b = blobs.get(f)
            if b and rx.findall(b):
                leaked.setdefault(f, []).append(label)
    print()
    if leaked:
        for f, labels in leaked.items():
            print("  !! %s CONTAINS an identifier from pubscan.local (%s)"
                  % (f, ", ".join(labels)))
            print("     A detector file that names what it hunts has disclosed it.")
        total += len(leaked)
    elif n_local:
        # Say the check RAN. Printing only on failure makes a pass and a
        # zero-pattern loop identical in the output, which is the same defect
        # this check exists to catch.
        print("    %-26s %3d file(s)  %4d pattern(s)   [clean]"
              % ("detector files vs local", len(SELF), n_local))
    else:
        print("    detector files vs local   NOT CHECKED -- no local patterns")

    # UNTRACKED BUT NOT IGNORED. Invisible to `git ls-files`, and this was the
    # entire exposure in a sibling repo: 22 such files carrying a real MAC,
    # house addresses and author paths, in a public repo, where a tracked-only
    # scan reported clean. Kept out of the total because they are not published
    # yet -- and reported loudly because they are one `git add -A` from being
    # exactly that, which is the state this tool is meant to be run before.
    others = untracked(args.repo)
    obody = {}
    for f in others:
        try:
            with open(os.path.join(args.repo, f), "rb") as fh:
                obody[f] = fh.read().decode("utf-8", "replace")
        except OSError:
            continue
    ohits = {}
    for label, rx in YOURS:
        find = rx if callable(rx) else rx.findall
        for f, b in obody.items():
            if find(b):
                ohits.setdefault(f, set()).add(label)
    print()
    if ohits:
        print("  !! %d untracked, UNIGNORED file(s) carry your identifiers."
              % len(ohits))
        print("     Not published yet. One `git add -A` away from being so.")
        for f in sorted(ohits)[:8]:
            print("        %-50s %s" % (f, ", ".join(sorted(ohits[f]))))
        if len(ohits) > 8:
            print("        ... and %d more" % (len(ohits) - 8))
    else:
        print("    untracked+unignored        %3d file(s) scanned, none carry identifiers"
              % len(obody))

    print()
    if total:
        print("%d occurrence(s) of your own identifiers are in tracked files." % total)
        print("Publishing discloses them. Genericise, or decide deliberately")
        print("that they are fine -- but decide, do not default.")
        if ohits:
            print("Plus %d untracked file(s) above, not published yet." % len(ohits))
    elif ohits and n_local:
        # Do not print a bare "found nothing" over a `!!` line. The bucket is
        # about unpublished files and the sentence was true as written, but a
        # skimmer sees the warning and the all-clear together and keeps the
        # second.
        print("No author identifiers in the TRACKED files, against %d structural"
              % (len(YOURS) - n_local))
        print("and %d author pattern(s). But %d untracked, unignored file(s) above"
              % (n_local, len(ohits)))
        print("do carry them, and are one `git add -A` from being published.")
    elif not n_local:
        # NEVER print a clean verdict from a run that could not look. Without
        # pubscan.local this scan has no hostname, domain, subnet or path to
        # search for, so "none found" would be a statement about the tool's
        # configuration wearing the clothes of a statement about the repo.
        print("NOTHING FOUND BY THE STRUCTURAL DETECTORS -- and the author-")
        print("specific ones did not run at all. This is NOT a clean result.")
        print("Restore ci/pubscan.local (see pubscan.local.example) and re-run")
        print("before treating this repo as checked.")
    else:
        print("No author identifiers found, against %d structural and %d author"
              % (len(YOURS) - n_local, n_local))
        print("pattern(s). That is not a promise the content is safe to publish,")
        print("only that this list did not match.")
    # 0 whether or not there were findings -- that half is a judgement call and
    # deliberately never fails a build. 2 when the scan could not run, which is
    # not a judgement call. See the module docstring.
    return 2 if not n_local else 0


if __name__ == "__main__":
    sys.exit(main())
