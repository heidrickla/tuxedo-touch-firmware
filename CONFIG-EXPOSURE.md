# /Config/ : the binding, and the patch that removes it

The Barracuda web server binds `/opt/tuxedo/configuration/` to the URL path
`Config`. That directory holds `Tuxedo.json` (with `SHARED_KEY`,
`UNAME_PASSWORD` and per-camera credentials), `webuseraccountsenc.json`, the
event log and the supervision log, and it survives reflashes.

**On this panel nothing is served: every request 404s.** The binding is
nonetheless unconditional in shipped code, which is why it is worth removing
rather than relying on.

## The code

`installVirtualDir` at `0x14598`, 1,208 bytes, called from `barracuda`. It
installs three disk-backed directories. The first two are gated; the third is
not.

| Insert | URL name | Serves | Gate |
|---|---|---|---|
| `0x14868` | `VideoFiles` | `/tmp/` | `allowVideoRecordingFromConfig()` at `0x147fc` |
| `0x148cc` | `Videos` | **`/mnt/sd`** | same gate |
| `0x14934` | **`Config`** | **`/opt/tuxedo/configuration/`** | **none** |

Every pc-relative string load in the function was mapped to its literal pool
slot to establish this, rather than inferred from proximity:

| Loaded at | String |
|---|---|
| `0x14814` | `/tmp/` |
| `0x14848` | `VideoFiles` |
| `0x14878` | `/mnt/sd` |
| `0x148a8` | `Videos` |
| `0x148dc` | `/opt/tuxedo/configuration/` |
| `0x14914` | `Config` |

Worth noting in passing: `Videos` binds the **SD card**, and the gate at
`0x147fc` branches to `0x148d0` when video recording is disallowed — which is
the start of the `Config` block. So turning video recording off skips the first
two directories and installs `Config` regardless.

The `Config` block runs unconditionally from `0x148d0`:

    0x148d0  ldr  r0, <DiskIo object>
    0x148d4  bl   DiskIo_constructor
    0x148dc  ldr  r1, ="/opt/tuxedo/configuration/"     ; pool 0x14a38
    0x148e0  bl   DiskIo_setRootDir
    0x148e4  cmp  r0, #0
    0x148e8  beq  0x1490c                 ; 0 = success, carry on and install
    0x148ec  ...  HttpTrace_printf / baFatalEf          ; failure is FATAL
    0x1490c  mov  r4, #0
    0x14914  ldr  r2, ="Config"                          ; pool 0x14a40
    0x14924  bl   HttpResRdr_constructor
    0x14930  mov  r0, sb                                 ; the HttpServer
    0x14934  bl   HttpServer_insertDir                   ; publishes it

Note the failure path calls `baFatalEf`. Since the panel runs, `DiskIo_setRootDir`
succeeded, so the directory really is constructed and inserted.

Found with `tuxelf.py`: the string `Config` occurs exactly once in the binary,
at `0x86160`, referenced from one place, the literal pool slot `0x14a40` that
`0x14914` loads.

## Measured behaviour

`/Config/CRCdata.json`, `/Config/Tuxedo.json`, `/Config/SystemConfig.txt`,
`/Config/AUTOMATION.txt` and `/Config/` all return **404**, unauthenticated and
authenticated, on port 80. Every one of those files exists on disk.

`/VideoFiles/` and `/Videos/` also 404. **All three disk-backed directories
behave the same**, which points at the `DiskIo`/`HttpResRdr` request path rather
than anything specific to `Config`. The cause is still unidentified.

So the honest statement has three parts, and dropping any one of them makes it
wrong:

1. The binding is unconditional in shipped code.
2. Nothing is served through it on this unit, with or without a session.
3. Why not is unknown, and it is common to all three directories, so it is not a
   property of `Config` that can be relied on.

## The patch

One instruction. Do not publish the directory:

| | |
|---|---|
| vaddr | `0x14934` |
| file offset | `0xc934` (vaddr − 0x8000, the convention across this binary) |
| before | `dc 67 01 eb` — `bl HttpServer_insertDir` |
| after | `00 00 a0 e1` — `mov r0, r0` |

The `DiskIo` object and the `HttpResRdr` are still constructed, so no
initialisation order changes and the fatal-error path is untouched; the
directory simply is never handed to the server. Nothing else calls into it: the
reader is not stored anywhere the rest of `installVirtualDir` reads.

**Not yet applied and not yet verified on hardware.** It is a candidate for the
next image rather than a reason to flash on its own, because the exposure is
latent rather than live. Verify after flashing by confirming `/Config/` still
404s and that the web UI, the video pages and the event handler are unaffected.

This supersedes the two unverified candidates near `0x14934` recorded in
`TUXEDO-VERIFIED.md`; that address was the right neighbourhood, and this is the
instruction.

## What is actually in that directory, and why the patch is worth carrying

The owner has no cameras on the panel; he uses UniFi. That was checked against
`Tuxedo.json` rather than assumed, and it changes two earlier claims.

**Downgraded.** `CAM_Login` and `CAM_Password` are **empty**. An earlier note
described per-camera credentials sitting in a world-readable file; there are
none to expose on this unit.

**Upgraded.** `DISCOVERY_SETTINGS` holds a `UNAME_PASSWORD` field in the form
`localadministrator,<password>` in **plaintext**, keyed by
`CUST_ID_MODEL: "Honeywell,*"`, alongside a `SHARED_KEY`. These are the
credentials the panel uses to log in to Honeywell-branded cameras it discovers,
so on this unit they are a **vendor default rather than the owner's secret**,
and with no Honeywell cameras present they open nothing here. The value is
deliberately not recorded in this repository.

That is still a plaintext administrative credential and a shared key in a
mode-644 file, on the partition that survives reflashes, inside the directory
`installVirtualDir` binds to `/Config` with no gate. The 404 is unexplained and
common to all three disk-backed directories, so it is not a control. **That is
the case for carrying the patch: not that anything leaks today, but that the
only thing preventing it is a behaviour nobody has explained.**

## The panel is inventorying the LAN

`IPCAMERAS` is not empty. It holds discovered devices that are not cameras:

    CAM_Mac "LaserJetPM426fd-6"   CAM_IP 203.0.113.227   an HP printer
    CAM_Mac "brother775D7251-1"   CAM_IP 198.51.100.246   a Brother printer

The second is on a **different subnet** from the panel, so discovery is not
confined to the panel's own segment. Each entry is stamped with guessed RTSP and
MJPEG paths and port 554.

Discovery is fully enabled for a feature with nothing attached:

    UPNP 1    SERCOMM 1    HONEYWELL_SERCOMM 1    EXTERNAL_CAMERAS 1
    CAM_REC_ENABLED 0    CAM_DISCOVERED 0    DEFAULT_CAMERA "NA"

`vidApp` is running, and `supervis` is listening on 6800 (`Tux_Server4Cam`),
both for cameras that do not exist.

So there is a straightforward reduction available with no loss of function:
turn the four discovery flags off. That stops the panel probing the network and
writing what it finds to a reflash-surviving file, and it takes the camera
subsystem out of use.

Two cautions before anyone edits `Tuxedo.json` by hand. It is validated against
`CRCdata.json`, and `validateCRCFileOnFileRead` self-heals from the `_sec` twin
on a mismatch, so a hand-edit is likely to be silently reverted. The supported
route is the panel's own camera settings screen. And `EXTERNAL_CAMERAS 1` with
`allowVideoRecordingFromConfig()` governs whether `VideoFiles` and `Videos` are
installed at all — `Videos` binds `/mnt/sd`, and the SD card is currently
mounted.

---

# Applied in v11, together with the camera listener

Both are single instructions, and **both offsets quoted in earlier analysis were
wrong**. Each was re-derived from the binary before being written.

| | `/Config` | camera listener |
|---|---|---|
| Binary | `opt/webserver/Barracuda` | `supervis` |
| Symbol | `installVirtualDir` | `serverThreadForCamera` |
| vaddr | `0x14934` | `0xc5e8` |
| **file offset** | **`0xc934`** | **`0x45e8`** |
| earlier claim | `0x7d3b1` (the key blob, not the code) | `0x4b88` |
| before | `dc 67 01 eb` `bl HttpServer_insertDir` | `b4 f4 ff eb` `bl pthread_create` |
| after | `00 00 a0 e1` `mov r0, r0` | `01 00 a0 e3` `mov r0, #1` |

`/Config`: the `DiskIo` and `HttpResRdr` are still constructed and the fatal
error path is untouched; the directory is simply never handed to the server.

Camera listener: `mov r0,#1` makes the following `cmp r0,#0` fail, so the
vendor's own error branch is taken. Verified that branch is safe before writing
anything, because `supervis` is the sole `/dev/watchdog` kicker and a wrong
assumption there is a boot loop:

    0xc5ec  cmp   r0, #0
    0xc5f4  ldrne r0, ="error in cerating serverThreadForCameraId"
    0xc600  b     0xc67c          <- logs and continues; no exit, no abort

Both verified present after the JFFS2 round trip. The patcher refuses to write
unless it finds the expected bytes, and keeps a `.prepatch` copy, which is
excluded from the image.

**Not yet on hardware.** Pushing the patched binaries to the running panel was
declined by the permission classifier, which is the right call for overwriting a
live alarm system's web server and supervisor. v11 is built and staged instead.
