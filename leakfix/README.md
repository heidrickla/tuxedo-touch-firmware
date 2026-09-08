# P15 leak fix: tooling and derivation

The vendor webserver leaked **1488 bytes per API request** and **7537 per
`/tuxedoapi.html` request**. Both now measure zero. `patches.tsv` carries the
114 resulting rows; this directory is how they were derived and verified,
because without it those rows are unexplained hex.

All 18 sites are vendor defects present in unmodified `324209e1`. None was
introduced by our patches — `attribute.py` proves it.

## The defect

libjson's `json_as_string()` and `json_write()` return **caller-owned** memory
that must be released with `json_free`. The image makes **391** and **521** such
calls against **28** `json_free`. The vendor's own correct site at `0x470e8`
shows the intended pattern. Six `json_as_string` ran per API request and none
was freed.

`json_free`, not `free`. They are different functions and using the wrong one
corrupts the heap.

On top of that, several buffers are abandoned at birth: the request parameter
tree is lost when `r7` — the only pointer to it — is overwritten at `0x29088`,
and two `json_write` results are destroyed by the return value of the very call
that consumes them.

## Tools

| tool | what it answers |
| --- | --- |
| `mkapifix.py` | builds the patched binary and emits the `patches.tsv` rows. Every site carries its rationale: why it leaks, why the fix is safe, which registers are live. Start here. |
| `leakprobe.py` | drives authenticated requests and fits RSS against request count. Reports the HTTP status distribution, because 200 requests that all 302 exercise nothing and read as "no leak". |
| `heapwalk.py` | histograms in-use glibc chunk sizes. Sample before and after N requests; a size growing by ~N is allocated once per request and never freed. |
| `chunkdiff.py` | dumps the *contents* of chunks that appeared between two snapshots. This is what named the leaks when execution tracing could not. |
| `scanmem.py` | counts a byte pattern in a live process. Send a marker in the request, count retained copies. |
| `findcave.py` | finds genuinely dead functions usable as code caves. |
| `attribute.py` | classifies each leak site vendor vs ours, and checks caves do not collide with existing patches. |
| `panelleak.py` | measures the live panel, tracking `[heap]` separately from total RSS. |
| `barra-sampler.sh` | long-run sampler for the panel. |
| `serve-traced.sh` | starts the emulator with qemu execution tracing restricted to an address range. |

## Traps these tools exist to avoid

**Chunk in-use is the NEXT chunk's PREV_INUSE bit.** Bit 0 of a chunk's own size
field describes the *previous* chunk. Reading it as "this chunk is live" gives a
plausible histogram right up until frees become common — which is exactly when
it matters. It reported "no growth at all" once the big leaks were fixed, while
~16 chunks per request were still leaking.

**A cave hunt must scan `b` as well as `bl`.** CSP page handlers are reached by a
tail branch from their registration thunk, and `get` reaches
`getPartitionStatus` the same way. A `bl`-only scan offered
`handlerequest_html076EF::service` — 18 KB of live page handler — as free space.
A cave qualifies only if nothing branches to it *and* every image word equal to
its address lies in the symbol-table tail. The second test alone rejected
`AsynchResp_dispSendEv`, whose address sits in an indirect-call slot.

**Warm up before measuring.** The startup working-set ramp is steep enough to
dominate a short run: a payload that truly leaks 2321 B/request read 4342 with
`--warmup 10` and 17326 with `--warmup 0`. Use `--warmup 200` and check that
consecutive runs agree.

**`-dfilter` reads `start-size` as start MINUS size.** Use `start..end`.

**Distinguish time-driven from work-driven growth.** The panel first read
~79 B/request. Running the same interval with *no* requests grew the heap
*more*. That figure was time-driven ramp divided by however many requests
happened to be sent — it would change with the send rate and mean nothing.

**Shell scripts written on Windows arrive on the panel as CRLF and fail
silently.** `INTERVAL=300\r` breaks `sleep`; `LOG=...tsv\r` names a different
file. Pipe through `tr -d '\r'`. Python on the build VM tolerates CRLF; the
panel's `/bin/sh` does not.

**Never match a process by a substring that your own command line contains.**
`case "$c" in *barra-sampler*)` over ssh matched the ssh command itself and
killed the session. Match a cmdline prefix, or identify by who holds the port.

## Verification performed

Under emulation, against the exact binary later deployed: API and
`/tuxedoapi.html` both 0 B/request, 2000 and 500 sustained requests with RSS
unchanged, responses checked by content rather than status, and a negative
control confirming the harness still reads ~1488 on an unpatched binary.

On the panel: `verify-panel.sh` passes all 134 rows, the P13 push stream denies
anonymous access with 401 on all four listeners and delivers frames when
authenticated, and a paired control (400 requests versus the same interval idle)
shows requests contribute no growth.
