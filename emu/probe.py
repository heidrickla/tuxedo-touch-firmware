"""Ask the shim for the push stream and report what came back.

Deliberately separate from the shim and deliberately dumb: a client that
retries, follows redirects or reconnects could hide the very failure this test
is looking for.
"""
import re
import socket
import sys
import time

tok = sys.argv[1]
hold = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0

try:
    s = socket.create_connection(("127.0.0.1", 8081), timeout=10)
except Exception as e:
    print("  client: connect failed: %s" % e)
    raise SystemExit(1)

s.sendall(
    (
        "GET /SimpleDebugger.interface/G. HTTP/1.1\r\n"
        "Host: p\r\n"
        "Authorization: Bearer %s\r\n\r\n" % tok
    ).encode()
)
s.settimeout(hold)

buf = b""
t0 = time.time()
while time.time() - t0 < hold and len(buf) < 8000:
    try:
        d = s.recv(2048)
    except Exception:
        break
    if not d:
        break
    buf += d
s.close()

status = buf.split(b"\r\n")[0].decode("latin-1", "replace") if buf else "(nothing)"
print("  client: %-28s %d bytes, %d frames"
      % (status, len(buf), len(re.findall(rb"statusMessageText", buf))))
