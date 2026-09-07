# Outbound connections the panel makes on its own

Observed 2026-09-06 on the live unit, read-only. Nothing was changed.

## ANSWERED by the owner: this is the Resideo mobile-app camera relay

**`108.170.102.188:10086` is the relay the Resideo phone app uses to pull camera
feeds from outside the LAN.** Lewis identified it; it is a real product feature,
not telemetry and not a stale address.

That resolves the whole question below, and it is worth being explicit about
which part of the original reading was wrong:

- **Wrong:** the framing as telemetry. That came from the vendor's filename
  `datacollect.txt` and nothing else. The document flagged it at the time as
  "an inference from a name, not a reading of a payload" -- which was the right
  caveat, and the inference was still wrong.
- **Wrong:** the suggestion the address might be stale and reallocated. It is
  the live Resideo relay.
- **Still true and unchanged:** the observation itself. `/tuxedo` really does
  retry `108.170.102.188:10086` continuously, the address really does come from
  a 16-byte bare-IP config file with no hostname, and the connection really
  never completes on this network.

**Why it never connects here, and why that is fine:** this panel has no cameras
attached -- Lewis uses UniFi cameras, which are not connected to the Tuxedo. So
the relay has nothing to serve. The retry loop is a feature idling against a
network that blocks it, for a capability this installation does not use.

**Nothing to do.** No change is warranted, and the options listed at the end of
this document are retained only to record that they were considered and
rejected.

---

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

`/etc/hosts` additionally maps a `Tux...` hostname to a public address:
`199.63.244.206  Tux002DD0006236`.

**It is NOT this panel's hostname, and the correction is more interesting than
the claim.** A Tuxedo's hostname is `Tux` followed by its own MAC with the
colons stripped, and this unit's differs from that entry. `Tux002DD0006236`
matches no panel the image ships to: it is present in the stock root filesystem
as shipped, and this unit's own hostname appears nowhere in that image. So the
vendor's `/etc/hosts` hardcodes some build-time device's name against the
AlarmNet relay address, and that entry is stale on every unit in the field.

Worth knowing before anyone "fixes" it: `00:2d:d0` reads as the Resideo OUI
`00:d0:2d` with the first two octet-pairs transposed, which is exactly what a
careless genericisation looks like. It is not one — the identical line is in the
untouched stock image.

## The bare IP, revisited

A hardcoded address with no hostname still means the destination cannot follow a
DNS change, which is a genuine fragility in a 2017 build -- if Resideo ever moves
the relay, this panel cannot follow it. But it is a durability question about a
real service, not evidence of anything going somewhere unexpected.

The earlier speculation here about reallocation is withdrawn.

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

## Options considered and rejected

Recorded so the reasoning is not repeated. **Leave it alone** is the answer.

Blanking `datacollect.txt` was considered before the address was identified. It
would break the mobile-app camera relay for anyone who does use it, and its
behaviour with an empty value was never tested. Do not do it.
