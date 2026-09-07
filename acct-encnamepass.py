"""What is EncNamePass a hash of?

/tuxedo calls MD5String from exactly the four account-setup paths, and the field
is 32 hex characters, so an MD5 of something built from the name and password is
the obvious hypothesis. Rather than chase the sprintf through more disassembly,
test it against the real file.

Only a BOOLEAN is reported per candidate: which construction reproduces the
stored digest, across all five accounts. No names, passwords or digests are
printed. This is the method SERVICES-6800-9443.md used for the RSA key -- search
for a match, compute a yes/no, record nothing.
"""
import hashlib
import json
import sys

sys.path.insert(0, "/work/repo-check")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from tuxelf import Elf

e = Elf("/work/extracted/root_stock/tuxedo")
key = e.d[e.v2o(0xD09654):e.v2o(0xD09654) + 16]
iv = e.d[e.v2o(0xD09664):e.v2o(0xD09664) + 16]
c = Cipher(algorithms.AES(key), modes.OFB(iv)).decryptor()
blob = open("/tmp/acct.enc", "rb").read()
doc = json.loads((c.update(blob) + c.finalize())
                 .decode("utf-8", "replace").rstrip("\x00").strip())
users = doc["WEBUSERS"]

CANDIDATES = {
    "md5(name + pass)":            lambda n, p: n + p,
    "md5(lower(name) + pass)":     lambda n, p: n.lower() + p,
    "md5(pass + name)":            lambda n, p: p + n,
    "md5(name + ',' + pass)":      lambda n, p: n + "," + p,
    "md5(name + ':' + pass)":      lambda n, p: n + ":" + p,
    "md5(name + ' ' + pass)":      lambda n, p: n + " " + p,
    "md5(lower(name) + ',' + pass)": lambda n, p: n.lower() + "," + p,
    "md5(name)":                   lambda n, p: n,
    "md5(pass)":                   lambda n, p: p,
}

print("testing %d constructions against %d accounts" % (len(CANDIDATES), len(users)))
hit = None
for label, build in CANDIDATES.items():
    ok = 0
    for u in users:
        want = u.get("EncNamePass", "").lower()
        got = hashlib.md5(build(u["userName"], u["passWord"]).encode()).hexdigest()
        if got == want:
            ok += 1
    mark = "MATCH" if ok == len(users) else ("partial" if ok else "")
    print("  %-32s %d/%d %s" % (label, ok, len(users), mark))
    if ok == len(users):
        hit = label

print()
print("result:", hit if hit else "no candidate matched -- it is not a plain MD5 of these")
