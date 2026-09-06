# Outbound connections the panel makes on its own

Observed 2026-09-06 on the live unit, read-only. Nothing was changed. **This is
a decision for the owner, not a defect to fix unasked.**

## What is happening

`/tuxedo` — the alarm application itself, not the web server — attempts an
outbound TCP connection to **`108.170.102.188:10086`** continuously. Sampled
three times over 60 s:

```
tcp  0  1  203.0.113.5:45989  108.170.102.188:10086  SYN_SENT  915/tuxedo
tcp  0  1  203.0.113.5:45993  108.170.102.188:10086  SYN_SENT  915/tuxedo
tcp  0  1  203.0.113.5:45994  108.170.102.188:10086  SYN_SENT  915/tuxedo
```

Every sample is `SYN_SENT` with an incrementing source port and none ever
reaches `ESTABLISHED`, so the connection is being blocked upstream and the panel
is retrying in a loop. **MEASURED.**

## Where the address comes from

Not the binary. `strings` over `tuxedo` and `Barracuda` finds no occurrence of
the address, the port, or any `.com`/`.net` hostname. It comes from the
configuration partition:

| file | size | contents |
|---|---:|---|
| `configuration/datacollect.txt` | 16 B | `108.170.102.188\0` |
| `configuration/datacollect_sec.txt` | — | same address, encrypted variant |
| `configuration/ipupdate.txt` | 16 B | `52.168.163.214\0\0` |

Both are **bare IP addresses with no hostname**, so no DNS lookup occurs and the
destination cannot follow a vendor DNS change. The filename `datacollect` is the
vendor's, not ours.

`/etc/hosts` additionally maps the panel's own hostname to a public address:
`199.63.244.206  Tux002DD0006236`.

## Why a bare IP is the interesting part

A hardcoded address in a 2017-era build cannot be re-pointed by the vendor. If
`108.170.102.188` has since been reallocated — it falls in `108.170.0.0/16`,
a range widely associated with Google, though current ownership was **not
verified here** — then the panel is periodically trying to open a connection to
whoever holds that address today, not to Honeywell.

That is the part worth weighing. Telemetry to the vendor is a policy question.
Telemetry to a stale address is a different question, because the recipient is
whoever the address belongs to now.

**What is NOT established:** what would be sent, and whether it contains anything
sensitive. The connection never completes on this network, so nothing has been
observed on the wire. The filename implies data collection; that is an inference
from a name, not a reading of a payload, and it should not be reported as more
than that.

## `/TotalConnect`

A third process, `/TotalConnect` (pid 1112, 175,888 bytes, parent `init`), runs
alongside `tuxedo` and `Barracuda`. It **listens on nothing** and holds 8 message
queues plus `/dev/watchdog`, including `/Q_ServCmdRcver` — the command queue into
the alarm application.

Incidentally this settles an open question in `WEBSERVER-REPLACEMENT.md` §5.1 by
existence proof: **a process other than Barracuda already opens the command
queue on this panel.** Three processes hold the boundary queues concurrently
(915 `tuxedo`, 1074 `Barracuda`, 1112 `TotalConnect`), so opening is not
exclusive. Only message *delivery* is one-receiver-per-message, which is why the
migration is a cutover rather than a coexistence — that reasoning is unchanged.

Queue permissions confirmed: `-rwxr-x--- root root`, so a replacement must run
as root. Barracuda already does.

## Options, if the owner wants them

Not done, and not to be done without a decision:

1. **Leave it.** The connection already fails on this network; the cost is a
   retry loop and some log noise.
2. **Blank `datacollect.txt`.** It lives on the config partition, which survives
   a reflash. Behaviour when the address is empty is **unknown** and would need
   testing — it might stop trying, or it might fail differently.
3. **Block it at the router**, which is effectively the current state, and the
   only option that needs no change to the panel at all.

Option 3 is what is already happening. Nothing here is urgent.
