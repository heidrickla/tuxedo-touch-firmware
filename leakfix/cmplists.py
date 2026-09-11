#!/usr/bin/env python3
"""Compare the client-derived endpoint list against the server's routing table.

The claim "the two lists agree" was committed after eyeballing a handful of rows.
This checks it. Client names come from the fenced blocks in TUXEDO-FINDINGS.md's
API section; server names from fieldpaths.py output.

Usage: cmplists.py <findings.md> <serverpaths.txt>
"""
import io
import re
import sys


def client_endpoints(path):
    text = io.open(path, encoding="utf-8", errors="replace").read()
    # Only the API section: from the "All paths are relative" line to the server section.
    start = text.find("All paths are relative")
    end = text.find("### The SERVER's routing table")
    if start < 0:
        raise SystemExit("could not find the client list section")
    body = text[start:end if end > start else len(text)]
    names = set()
    for block in re.findall(r"```(.*?)```", body, re.S):
        for line in block.splitlines():
            line = line.strip()
            if not line:
                continue
            path_part = line.split()[0]
            # rows like "Administration/AddIPURL / UpdateIPURL / ViewIPURL"
            if " / " in line:
                head = line.split()[0]
                base = head.rsplit("/", 1)[0] if "/" in head else ""
                for alt in re.split(r"\s+/\s+", line.split("  ")[0]):
                    alt = alt.strip()
                    if not alt:
                        continue
                    names.add(alt if "/" in alt else (base + "/" + alt if base else alt))
                continue
            names.add(path_part)
    return {n.strip("/") for n in names if n and not n.startswith("#")}


def server_endpoints(path):
    names = set()
    for line in io.open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line.startswith("/system_http_api/"):
            continue
        container = "(container)" in line
        p = line.split()[0][len("/system_http_api/"):]
        if p.startswith("API_REV01/"):
            p = p[len("API_REV01/"):]
        elif p == "API_REV01":
            continue
        names.add((p, container))
    return names


def main():
    client = client_endpoints(sys.argv[1])
    server_all = server_endpoints(sys.argv[2])
    server_leaves = {p for p, c in server_all if not c}
    server_names = {p for p, _ in server_all}

    print("client-derived endpoints : %d" % len(client))
    print("server leaves            : %d" % len(server_leaves))
    print()
    only_client = sorted(n for n in client if n not in server_names)
    only_server = sorted(n for n in server_leaves if n not in client)
    print("IN CLIENT LIST BUT NOT ROUTED BY SERVER (%d):" % len(only_client))
    for n in only_client:
        print("   ", n)
    print()
    print("ROUTED BY SERVER BUT ABSENT FROM CLIENT LIST (%d):" % len(only_server))
    for n in only_server:
        print("   ", n)


if __name__ == "__main__":
    main()
