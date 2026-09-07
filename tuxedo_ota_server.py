#!/usr/bin/env python3
"""
A self-hosted firmware update server for the Honeywell Tuxedo Touch.

The panel contains a complete OTA client. It asks an AlarmNet redirector where
to fetch updates, pulls a product XML manifest, then downloads each `.hdr` file
onto its own inserted SD card with HTTP byte-range requests and reprograms
itself. Redirecting it needs no binary patching: `/etc/nsswitch.conf` reads
`hosts: files nisplus nis dns`, so an `/etc/hosts` entry on the panel beats DNS.

    python tuxedo_ota_server.py --dir ./payload --port 80

Then, on the panel, point one of these at this machine's address:

    auiredir1.alarmnet.com   auiredir2.alarmnet.com
    auiredir3.alarmnet.com   auiredirtest.alarmnet.com

The flashed image ships a commented block in `/etc/hosts` for exactly this.
`/srv_info.conf` is the other lever and is better if the same name should
resolve to a different address.

SAFETY

This serves files. It cannot reach the panel on its own, and the panel will
not contact it until someone edits the panel's own hosts file. Until then this
is an ordinary local web server.

The client is forgiving by design: an HTTP error or a DNS failure each start a
two-hour retry timer and neither is fatal. A server that is absent, wrong or
switched off costs the panel nothing.

WHAT IS AND IS NOT KNOWN

The manifest field names, the two request shapes and the panel's self-identifi-
cation were recovered from the application binary and are recorded in
`docs/TUXEDO-BUILD.md` §11. **The redirector handshake has not been observed**, so
`/redirect` below is a guess at the shape and is logged rather than trusted.
Run with `--observe` and point the panel at it to capture what it actually
sends before relying on any of this.

Nothing here has been tested against a panel.
"""

import argparse
import datetime
import http.server
import os
import re
import socketserver
import struct
import sys
import threading
import xml.sax.saxutils as saxutils

HDR_SIZE = 128

# Recovered from the binary, in the order the parser reads them.
MANIFEST_FIELDS = ("size", "checksum", "folderpath", "version",
                   "filenumber", "platform", "notes")

# What this panel calls itself: `Local ver-%s,boardType-%s`
PLATFORM = "TUXEDOPLUSVA"


def header_checksum(path, start=HDR_SIZE, length=None):
    """ProgCV's checksum: big-endian 16-bit words into a 32-bit accumulator,
    folded twice at the end, complemented. See tuxedo_hdr.py."""
    if length is None:
        length = os.path.getsize(path) - start
    acc = 0
    with open(path, "rb") as f:
        f.seek(start)
        left = length
        while left > 0:
            buf = f.read(min(left, 1 << 24))
            if not buf:
                break
            even = buf[:len(buf) & ~1]
            acc += sum(struct.unpack(f">{len(even)//2}H", even))
            left -= len(buf)
    acc %= 1 << 32
    acc = (acc >> 16) + (acc & 0xFFFF)
    acc = acc + (acc >> 16)
    return (~acc) & 0xFFFF


def read_hdr(path):
    """Pull the vendor header fields a manifest entry needs."""
    h = open(path, "rb").read(HDR_SIZE)
    return {
        "magic":    h[0:8].split(b"\0")[0].decode("latin-1"),
        "size":     struct.unpack_from("<I", h, 0x08)[0],
        "checksum": struct.unpack_from("<H", h, 0x14)[0],
        "filename": h[0x30:0x3d].split(b"\0")[0].decode("latin-1"),
        "version":  h[0x3d:0x4e].split(b"\0")[0].decode("latin-1"),
        "type":     h[0x4e:0x52].split(b"\0")[0].decode("latin-1"),
        "platform": h[0x52:0x60].split(b"\0")[0].decode("latin-1"),
    }


def scan(payload_dir):
    """Describe every .hdr in the payload directory, verifying each one."""
    out = []
    for name in sorted(os.listdir(payload_dir)):
        if not name.lower().endswith((".hdr", ".hex")):
            continue
        path = os.path.join(payload_dir, name)
        entry = {"name": name, "path": path, "bytes": os.path.getsize(path)}
        if name.lower().endswith(".hdr"):
            h = read_hdr(path)
            entry.update(h)
            got = header_checksum(path, HDR_SIZE, h["size"])
            entry["computed"] = got
            entry["ok"] = (got == h["checksum"]
                           and entry["bytes"] == HDR_SIZE + h["size"])
        else:
            entry["ok"] = True
        out.append(entry)
    return out


def manifest_xml(entries, version, folderpath, notes):
    """Best-effort product XML. Field NAMES are confirmed from the binary;
    the element nesting is NOT, because no real manifest was ever captured."""
    total = sum(e["bytes"] for e in entries)
    esc = saxutils.escape
    rows = "\n".join(
        f"    <file><name>{esc(e['name'])}</name>"
        f"<size>{e['bytes']}</size>"
        f"<checksum>{e.get('checksum', 0):04x}</checksum></file>"
        for e in entries)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<product>\n"
        f"  <size>{total}</size>\n"
        f"  <checksum>0</checksum>\n"
        f"  <folderpath>{esc(folderpath)}</folderpath>\n"
        f"  <version>{esc(version)}</version>\n"
        f"  <filenumber>{len(entries)}</filenumber>\n"
        f"  <platform>{esc(PLATFORM)}</platform>\n"
        f"  <notes>{esc(notes)}</notes>\n"
        "  <files>\n" + rows + "\n  </files>\n"
        "</product>\n"
    )


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "TuxedoOTA/0.1"
    entries = []
    payload_dir = "."
    version = ""
    notes = ""
    observe = False

    def log_message(self, fmt, *a):
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        sys.stderr.write(f"  {stamp}  {self.client_address[0]}  {fmt % a}\n")

    def _dump_request(self):
        """Everything the panel sent. This is the point of --observe."""
        sys.stderr.write(f"\n--- {self.command} {self.path} ---\n")
        for k, v in self.headers.items():
            sys.stderr.write(f"    {k}: {v}\n")
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            sys.stderr.write(f"    body: {self.rfile.read(n)!r}\n")
        sys.stderr.write("---\n")

    def _send(self, body, ctype="application/octet-stream", status=200,
              extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _serve_range(self, path):
        """The panel fetches files with `Range: bytes=%d-%d`."""
        total = os.path.getsize(path)
        rng = self.headers.get("Range", "")
        m = re.match(r"bytes=(\d+)-(\d*)", rng.replace(" ", ""))
        if not m:
            with open(path, "rb") as f:
                self._send(f.read())
            return
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else total - 1
        end = min(end, total - 1)
        if start > end:
            self._send(b"", status=416)
            return
        with open(path, "rb") as f:
            f.seek(start)
            chunk = f.read(end - start + 1)
        self._send(chunk, status=206, extra={
            "Content-Range": f"bytes {start}-{end}/{total}",
            "Accept-Ranges": "bytes",
        })

    def do_GET(self):
        if self.observe:
            self._dump_request()
        name = os.path.basename(self.path.split("?")[0])

        # The redirector step. SHAPE UNCONFIRMED - logged, not trusted.
        if "redir" in self.path.lower() or self.path in ("/", ""):
            host = self.headers.get("Host", "").split(":")[0]
            body = f"{host}\n".encode()
            self.log_message("redirector hit (shape unconfirmed) -> %s", host)
            self._send(body, "text/plain")
            return

        if name.lower().endswith(".xml"):
            xml = manifest_xml(self.entries, self.version, "/", self.notes)
            self._send(xml.encode(), "text/xml")
            return

        for e in self.entries:
            if name == e["name"]:
                self._serve_range(e["path"])
                return
        self._send(b"not found\n", "text/plain", 404)

    def do_POST(self):
        if self.observe:
            self._dump_request()
        self._send(b"", "text/plain", 200)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dir", default="payload",
                    help="directory holding the .hdr files to serve")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--version", default="",
                    help="version to advertise; defaults to the app2 header's")
    ap.add_argument("--notes", default="Self-hosted update.")
    ap.add_argument("--observe", action="store_true",
                    help="dump every request in full; use this FIRST, to learn "
                         "the redirector handshake before trusting anything")
    a = ap.parse_args()

    if not os.path.isdir(a.dir):
        sys.exit(f"no such directory: {a.dir}")
    entries = scan(a.dir)
    if not entries:
        sys.exit(f"no .hdr or .hex files in {a.dir}")

    print(f"payload from {a.dir}:")
    bad = 0
    for e in entries:
        if e.get("magic"):
            state = "ok" if e["ok"] else "BAD"
            if not e["ok"]:
                bad += 1
            print(f"  {state:3} {e['name']:16} {e['bytes']:>10} bytes  "
                  f"{e['magic']}  {e['version']}  "
                  f"hdr=0x{e['checksum']:04x} computed=0x{e['computed']:04x}")
        else:
            print(f"  ok  {e['name']:16} {e['bytes']:>10} bytes  (raw)")
    if bad:
        sys.exit(f"\n{bad} file(s) would be rejected by the panel. "
                 f"Fix them with tuxedo_hdr.py before serving.")

    version = a.version or next(
        (e["version"] for e in entries if e["name"].startswith("app2")), "")
    Handler.entries = entries
    Handler.payload_dir = a.dir
    Handler.version = version
    Handler.notes = a.notes
    Handler.observe = a.observe

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    print(f"\nadvertising version {version!r} for platform {PLATFORM}")
    print(f"serving on {a.bind}:{a.port}"
          + ("  [OBSERVE MODE: dumping every request]" if a.observe else ""))
    print("the panel will not contact this until its own /etc/hosts points "
          "an auiredir name here\n")
    with Server((a.bind, a.port), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
