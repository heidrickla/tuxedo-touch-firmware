"""Does the console page's keypad exist in the markup at all?

This decides whether making Barracuda consume reply type 20 would actually give
a working keypad. If the buttons are static markup they should render with or
without a display feed, so their absence would be a SEPARATE defect and the
type-20 work alone would not fix what Lewis saw. If the page builds its keypad
only after a feed arrives, type 20 is the whole story.
"""
import os
import re
import sys

sys.path.insert(0, "/work/fwcheck")
from leakprobe import TuxedoProbe

pw = open("/tmp/pw").read().strip()
# The panel account name is deliberately kept OUT of this repo -- aff1f99
# removed it from leakprobe.py and gave pubscan a detector for it. Pass it in.
user = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TUXEDO_USER")
if not user:
    raise SystemExit("usage: consolepage.py <panel-user>   (or set TUXEDO_USER)")
p = TuxedoProbe("127.0.0.1", user, pw, scheme="http")
p.login()

PATTERNS = (
    (r"<input[^>]*type\s*=\s*.?button", "input type=button"),
    (r"<button", "button tags"),
    (r"onclick", "onclick handlers"),
    (r"sendkey", "sendKey refs"),
    (r"keypad", "keypad refs"),
    (r"[Tt]ype=19", "Type=19 console requests"),
    (r"line1|line2|dispText|displayLine", "display-text refs"),
    (r"<img", "img tags"),
    (r"<script", "script blocks"),
)

for page in ("/consolekeypad.html", "/console.html"):
    try:
        # _open returns (status, headers, body) and does not carry cookies
        # itself, so the session must be passed explicitly.
        status, _hdrs, body = p._open(p.base + page,
                                     headers={"Cookie": p.session_cookie})
        print("  %s -> HTTP %s" % (page, status))
    except Exception as e:
        print("  %s -> ERROR %s" % (page, e))
        continue
    b = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    print("  --- %s : %d bytes ---" % (page, len(b)))
    for pat, label in PATTERNS:
        print("      %-28s %d" % (label, len(re.findall(pat, b, re.I))))
    # the digits a keypad must have
    digits = sum(1 for d in "0123456789" if re.search(r"[>\"']\s*%s\s*[<\"']" % d, b))
    print("      %-28s %d of 10" % ("digit labels present", digits))
