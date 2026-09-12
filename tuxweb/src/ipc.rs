//! The IPC boundary with `/tuxedo`: 556-byte replies in, 404-byte commands out.
//!
//! Both layouts are recovered from the binaries and recorded in
//! `WEBSERVER-REPLACEMENT.md`; the command codes are in `commands.tsv`.
//!
//! The reply decoder cannot be tested against a captured corpus the way the
//! frame codec was — reading the reply queue TAKES the message, so capturing
//! replies would starve the vendor server. What can be tested, and is below, is
//! the reply -> frame formatting: synthesise the reply the panel must have sent
//! and assert the frame text comes out byte-identical to one actually captured
//! off the wire.

/// Replies are fixed-size on the queue: `osal_MqRecv(q, buf, 0x22c)`.
pub const REPLY_LEN: usize = 556;
/// Commands likewise: `mq_send(mqd, buf, 0x194, 1)`.
pub const COMMAND_LEN: usize = 404;

/// A reply from `/tuxedo`.
///
/// Offsets confirmed at the receive site in `gettuxedoIPCCommFunc`:
/// `ldr r8,[sp,#0x278]` is `+0x04`, `add sl,r6,#0xe` is the text, and the
/// `ldrb` from `+0x0E` is why `state` is the FIRST BYTE OF THE TEXT rather
/// than a field of its own.
///
/// **This layout is not universal, and reading it as though it were is a
/// mistake waiting to happen.** The 556 bytes are a union: `session` at
/// `+0x00` and `msg_type` at `+0x04` hold for every message, but what follows
/// depends on the type. `CReceiverThread::registerclient()` @`0x13c2f8` builds
/// the msgType 504 reply with the current partition at `+0x90`, a partition
/// description `strcpy`d to `+0x91`, and single bytes at `+0xaf` (CAL
/// implementation), `+0xb0` (arming modes `& 8`), `+0xb1` (operation mode),
/// `+0xb2` (total partitions), `+0xb4` (Z-Wave controller status) and `+0xb8`
/// (RIS supported). Nothing of interest sits at `+0x0E` in that one.
///
/// So `parse` is right for the status path it was derived from, and must not be
/// pointed at a 504 and believed.
///
/// The rest is decoded. `reply-layouts.py` reads all 78 builders -- the
/// `/tuxedo` functions that pass `0x22c` to `osal_MqSend` -- over their
/// control-flow graphs and prints one map per send site. The result is
/// `reply-layouts.txt`: 92 sites, 20 msgTypes. Consult it before assuming an
/// offset. Two of its results bear directly on this struct:
///
/// * **msgType 20 does put its text at `+0x0E`.** `wsltHandleRawDataFromPanel`
///   `strcpy`s then `strcat`s it there from `apl_getEcpConsoleModeData()`, so
///   `parse` is right for the console-mode message as well as for status.
/// * **`arg` is a container, not a meaning.** On `sltSendChangedPartitionStatus`
///   (msgTypes 21 and 22) `+0x08` is `PanelIsTalking() ? GetOnlineStatus() : -1`
///   (decompiled at `0x144880`, 2026-09-12), so the observed `0:21:1:fe:...`
///   frame means *online and talking*. It is NOT the partition: that function
///   sends only when `GetCurrentPartition()` matches, so one partition is ever
///   on the stream. The same function picks the type: **21 while
///   `GetOnlineStatus() == 1`, 22 otherwise** (`SERV_PANEL_OFFLINE_MSG_BROADCAST`
///   -- the VISTA reporting itself busy, downloading or offline, values 2..4,
///   which `HandlePanelStatus` copies out of the panel's own status response).
///   `-1` is a different fact: the ECP receiver has stopped hearing the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub session: u32,
    pub msg_type: u32,
    /// `+0x08`, a 32-bit word the vendor prints with `%d`, so `-1` is on the
    /// wire as `-1` and must be formatted SIGNED (`push_int`). Per-type: on
    /// msgTypes 21/22 (`sltSendChangedPartitionStatus`) it is the online
    /// status, or `-1` when the panel is not talking. See `reply-layouts.txt`.
    pub arg: u32,
    /// From `+0x0E`, NUL-terminated, latin-1. Not utf-8: the first byte is
    /// commonly 0xFE or 0xFF.
    pub text: Vec<u8>,
}

impl Reply {
    pub fn parse(buf: &[u8]) -> Option<Reply> {
        if buf.len() < 0x0F {
            return None;
        }
        let w = |o: usize| {
            u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
        };
        let tail = &buf[0x0E..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        Some(Reply {
            session: w(0x00),
            msg_type: w(0x04),
            arg: w(0x08),
            text: tail[..end].to_vec(),
        })
    }

    /// The `0xFE`/`0xFF` state byte, which is simply `text[0]`.
    pub fn state_byte(&self) -> Option<u8> {
        self.text.first().copied()
    }

    /// A msgType 504 read at the offsets a 504 actually uses.
    ///
    /// `parse` is the status-path view and is wrong here in a way that is easy
    /// to miss: it takes `arg` from `+0x08` and the text from `+0x0E`, and
    /// `registerclient` writes NEITHER. Its payload is the current partition
    /// at `+0x90` and the partition description `strcpy`d to `+0x91`
    /// (`reply-layouts.txt`), and Barracuda's builder at `0xf638` reads
    /// exactly those — `ldrb [sp,#0x304]` and `add r6,r6,#0x91` against a
    /// buffer based at `sp+0x274`. Using `parse` for a 504 puts uninitialised
    /// stack in the frame's third field.
    pub fn parse_504(buf: &[u8]) -> Option<Reply> {
        if buf.len() < REPLY_LEN {
            return None;
        }
        let w = |o: usize| {
            u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
        };
        let tail = &buf[0x91..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        Some(Reply {
            session: w(0x00),
            msg_type: w(0x04),
            arg: buf[0x90] as u32,
            text: tail[..end].to_vec(),
        })
    }

    /// The four trailing values of a 504 frame, in the order the builder
    /// pushes them: `+0xaf` panel CAL implementation, `+0xb1` operation mode,
    /// `+0xb2` total partitions, `+0xb4` Z-Wave controller status.
    ///
    /// All four come from the reply. **None is Barracuda-private state**, so a
    /// replacement can emit this frame from the queue message alone — which is
    /// what `WEBSERVER-REPLACEMENT.md` §5.11 had recorded as unknown.
    /// `+0xb0` and `+0xb8` are written by `registerclient` but the frame
    /// builder does not read them.
    pub fn registration_extra(buf: &[u8]) -> Option<[u32; 4]> {
        if buf.len() < REPLY_LEN {
            return None;
        }
        Some([
            buf[0xAF] as u32,
            buf[0xB1] as u32,
            buf[0xB2] as u32,
            u32::from_le_bytes([buf[0xB4], buf[0xB5], buf[0xB6], buf[0xB7]]),
        ])
    }
}

/// A command to `/tuxedo`. `code` is `+0x04`; `p1` and `p2` are `+0x08` and
/// `+0x0C`, whose meaning is per-command — for the touch-simulate command they
/// are x/y coordinates, so they are deliberately not named here.
///
/// **For the arming commands, `p2` (+0x0C) is the USER CODE.** Read out of
/// `sltRequestArmStay` @`0x140e44` in `/tuxedo`:
///
/// ```text
/// 140e70  ldrb  r3, [r6, r5]   ; quick-arm table, indexed by partition - 1
/// 140e78  cmp   r3, #0
/// 140e7c  ldreq r3, [pc,#428]  ; == 0 -> the constant 0xFFFF
/// 140e80  ldrne r3, [r4, #12]  ; != 0 -> the code from the request at +0x0C
/// ```
///
/// So `0xFFFF` is the quick-arm sentinel and anything else is a literal code.
/// Sending `p2 = 0` asks the panel to arm with code **zero**, which it declines --
/// that is exactly what the 2026-09-11 window measured (`USER CODE DECLINED`), and
/// it was the sender's fault, not the protocol's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub head: u32,
    pub code: u32,
    pub p1: u32,
    pub p2: u32,
}

impl Command {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![0u8; COMMAND_LEN];
        v[0x00..0x04].copy_from_slice(&self.head.to_le_bytes());
        v[0x04..0x08].copy_from_slice(&self.code.to_le_bytes());
        v[0x08..0x0C].copy_from_slice(&self.p1.to_le_bytes());
        v[0x0C..0x10].copy_from_slice(&self.p2.to_le_bytes());
        v
    }
}

/// Command codes verified individually. The rest live in `commands.tsv` and are
/// marked there as needing a handler read before being relied on.
pub mod cmd {
    pub const ARM_AWAY: u32 = 1;
    pub const ARM_STAY: u32 = 2;
    pub const DISARM: u32 = 3;
    pub const CONSOLE_MODE: u32 = 19;

    /// Stage 7b, the read-only queries. Each name is the handler `commands.tsv`
    /// records for the code, so a wrong constant is caught by reading one line
    /// rather than by watching a panel do something unexpected. None of these four
    /// changes panel state.
    pub const PARTITION_STATUS: u32 = 5; // sltRequestPartitionStatus
    pub const ALL_ZONE_STATUS: u32 = 12; // sltRequestAllZoneCurrStatus
    /// Paged: the reply arrives as more than one message.
    pub const EVENT_LOG_UPLOAD: u32 = 17; // sltRequestEventLogUpload
    pub const HOME_PART_DETAILS: u32 = 18; // sltRequestGetHomePartDetails

    /// Stage 7d, arming. `commands.tsv` handler names, all four:
    /// sltRequestArmAway, sltRequestArmStay, sltRequestDisarm, sltRequestArmNight.
    /// ARM_AWAY/ARM_STAY/DISARM are declared above; night completes the set.
    pub const ARM_NIGHT: u32 = 4; // sltRequestArmNight

    /// Stage 7c, and the pair most easily got backwards.
    ///
    /// MEASURED (`RELEASES.md`): `cmd 502 -> BACK`, `cmd 503 -> HOME`, the latter
    /// logged as "THE PANEL RETURNED TO THE HOME SCREEN". The stage plan described
    /// them as "502/503 (home/back)", which reads as 502=home and is wrong.
    ///
    /// Both are forwarded to the panel ONLY when `getConsoleMode() == 0`, so a
    /// console-mode command first can suppress them. Both also reach
    /// `home_back_press()`, which zeroes `F7_Mesgs_enabled` -- sending either
    /// switches the broadcast firehose off for every consumer, exactly as a 501
    /// does. Send them last or not at all.
    pub const BACK: u32 = 502;
    pub const HOME: u32 = 503;
    /// Registering DISCARDS every queued reply: `registerclient`'s first act is
    /// `osal_MqFlush`.
    pub const REGISTER: u32 = 500;
    /// The other half of 500, and what makes a window leave no trace.
    ///
    /// `unregisterclient()` @`0x13c00c` unconditionally zeroes BOTH
    /// `clients_connected` and `F7_Mesgs_enabled`. It is NOT a refcount, so one 501
    /// switches the broadcast firehose off for every consumer, not just for the
    /// sender -- the same byte a Home or Back press clears. Send it to leave the
    /// panel as it was found; do not send it while anything else is expected to
    /// still be watching.
    pub const UNREGISTER: u32 = 501;
}

// -- reply -> legacy frame text ------------------------------------------
//
// The vendor formats with `bprintf(session, fmt, …)` and passes the ':'
// separator as an ARGUMENT rather than putting it in the format string. The
// formats below are the vendor's own, from the handlers named in each comment.

/// One `%d` conversion: the vendor passes each 32-bit word to `bprintf` as a
/// signed int, so `+0x08 = -1` (panel not talking) prints as `-1`. Formatting
/// the word unsigned put `4294967295` there instead -- a value the consumer's
/// dead-link test (`panel_status_code == -1`) can never match. Neither capture
/// holds a negative field, which is why the byte-for-byte replay did not catch
/// it; `status_frame_prints_a_negative_arg_as_the_vendor_does` now does.
fn push_int(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice((v as i32).to_string().as_bytes());
}

/// msgType 21, handler `0xda80`: `%d%s%d%s%d%s%x%s%s%s%d`
/// = session : type : arg : state-as-HEX : text : quick-arm.
pub fn frame_status(r: &Reply, quick_arm: u32) -> Vec<u8> {
    let mut o = Vec::new();
    push_int(&mut o, r.session);
    o.push(b':');
    push_int(&mut o, r.msg_type);
    o.push(b':');
    push_int(&mut o, r.arg);
    o.push(b':');
    // %x of the state byte -- lowercase hex, no padding, as printf gives
    o.extend_from_slice(format!("{:x}", r.state_byte().unwrap_or(0)).as_bytes());
    o.push(b':');
    o.extend_from_slice(&r.text);
    o.push(b':');
    push_int(&mut o, quick_arm);
    o
}

/// msgTypes 22 and 18, handlers `0xd9b8` and `0xf1bc`: `%d%s%d%s%s%s%d`
/// = session : type : text : trailing value.
///
/// 18 and 22 share this format, so a decoder keyed on format shape alone would
/// conflate them.
///
/// **For msgType 22 the trailing value is a real one.** Read off the handler's
/// argument set-up (disassembled 2026-09-12): `ldr r3,[sp,#0x27c]` is `+0x08`
/// of the buffer at `sp+0x274`, stored at `[sp,#16]` as the seventh conversion;
/// `r6 + 14` is the text. So the frame is `session:22:<flag><css><text>:<arg>`
/// with `arg` the `PanelIsTalking() ? GetOnlineStatus() : -1` word the same
/// `/tuxedo` function writes for a 21 -- and then TWO `frame_filler` copies
/// (`mvn r7,#0` at `0xda24`, two `bprintf`s at `0xda40` and `0xda60`), not the
/// three a 21 gets. The vendor takes this arm only when the reply's session is
/// 0, then `setPartStatus(22, text, arg)` and `setpanelOnline(0)`.
///
/// **`trailing` is the reply's `+0x08`, and for msgType 18 nothing initialises
/// it.** `sltSendNewPartitionDetails` @`0x13e0c4` does `sub sp,sp,#0x250`, then
/// `stmib sp,{r2,r3}` — session and msgType only — and `sprintf`s the text to
/// `+0x0E`. There is no `memset`, and `+0x08` is never written, yet Barracuda
/// prints it (`ldr r3,[sp,#0x27c]` against a buffer at `sp+0x274`). The `2`
/// that appears in all 12 captured `0:18:` frames is stale stack that happens
/// to be stable, not a value the panel computed.
///
/// So **pass this field through verbatim; never synthesise or interpret it.**
/// A consumer reading meaning into the trailing field of a typed frame is
/// reading uninitialised memory.
pub fn frame_typed(r: &Reply, trailing: u32) -> Vec<u8> {
    let mut o = Vec::new();
    push_int(&mut o, r.session);
    o.push(b':');
    push_int(&mut o, r.msg_type);
    o.push(b':');
    o.extend_from_slice(&r.text);
    o.push(b':');
    push_int(&mut o, trailing);
    o
}

/// msgType 504, handler `0xf638`: `%d%s%d%s%d%s%s%s%d%s%d%s%d%s%d` — fifteen
/// conversions, eight fields with seven `':'` between them.
///
/// This is the registration reply, produced by `/tuxedo`'s `registerclient`
/// after it flushes the reply queue.
///
/// `r.arg` here is the CURRENT PARTITION, from the reply's `+0x90` — not
/// `+0x08`, which a 504 never writes. Build the argument with
/// [`Reply::parse_504`], not [`Reply::parse`].
///
/// `extra` is four values, not five, and their order is the order the builder
/// at `0xf638` pushes them: `+0xaf` panel CAL implementation, `+0xb1`
/// operation mode, `+0xb2` total partitions, `+0xb4` Z-Wave controller status.
/// Use [`Reply::registration_extra`]. The previous wording named five values
/// including the current partition and put the Z-Wave status first; the array
/// has always been four long, and the current partition is the `arg` field.
pub fn frame_registration(r: &Reply, extra: [u32; 4]) -> Vec<u8> {
    let mut o = Vec::new();
    push_int(&mut o, r.session);
    o.push(b':');
    push_int(&mut o, r.msg_type);
    o.push(b':');
    push_int(&mut o, r.arg);
    o.push(b':');
    o.extend_from_slice(&r.text);
    for v in extra {
        o.push(b':');
        push_int(&mut o, v);
    }
    o
}

/// The registration frame repeated with `-1` in the type slot.
///
/// The panel follows a registration the same way it follows a status: with
/// copies carrying `-1` instead of the message type. Same fields, so the only
/// difference is what goes in that one position — which is why the type is
/// printed rather than taken from the reply.
pub fn frame_registration_filler(r: &Reply, extra: [u32; 4]) -> Vec<u8> {
    let mut o = Vec::new();
    push_int(&mut o, r.session);
    o.extend_from_slice(b":-1:");
    push_int(&mut o, r.arg);
    o.push(b':');
    o.extend_from_slice(&r.text);
    for v in extra {
        o.push(b':');
        push_int(&mut o, v);
    }
    o
}

/// The `-1` filler, `%d%s%d%s%s` with `mvn r5,#0` in the type position.
///
/// Emitted three times after a msgType **21** status frame -- deliberate, not a
/// transport quirk. NOT after every status: a msgType 18 (`frame_typed`) gets
/// **zero** fillers, and a 504 is followed by three `frame_registration_filler`
/// (not this one). The per-type counts are measured over both capture fixtures
/// by `push::tests::every_reply_reproduces_its_captured_run`; an earlier version
/// of this line said "after every status frame", which was too broad.
pub fn frame_filler(r: &Reply) -> Vec<u8> {
    let mut o = Vec::new();
    push_int(&mut o, r.session);
    o.extend_from_slice(b":-1:");
    o.extend_from_slice(&r.text);
    o
}

/// msgType 20, the keypad LCD, handler at `0xdb8c` (the `bcc` range arm for
/// types below 21 — invisible to an equality scan, `TRAPS.md` §2). Decompiled
/// and its literals resolved 2026-09-12:
///
/// ```text
/// fmt  0x85304  "%d%s%d%s%s"     args: session, ":", 20, ":2", text'
/// sep  0x84f5c  ":"              the find() needle
/// sep2 0x852f4  ":2"             the SECOND separator is the literal ":2" —
///                                the "2" a consumer sees is not a field
/// rep  0x545aac "-"              replace(pos, 1, "-") on the FIRST ':' in the
///                                text, only when pos > 0
/// ```
///
/// So the wire frame is `session:20:2<text'>` with `text'` the LCD text after
/// its first `:` (if any, and not at index 0) becomes `-`, which keeps a colon
/// in the display from splitting the frame. The vendor only takes this arm when
/// the reply's session is 0, and follows it with THREE `frame_console_unsolicited`
/// copies of the RAW text (the `-1` id; `mvn r4,#0`, raw pointer in `r6`), then
/// `setConsoleMessage(20, text')` for its console page.
pub fn frame_console(r: &Reply) -> Vec<u8> {
    let mut text = r.text.clone();
    if let Some(pos) = text.iter().position(|&b| b == b':') {
        if pos > 0 {
            text[pos] = b'-';
        }
    }
    let mut o = Vec::new();
    push_int(&mut o, r.session);
    o.extend_from_slice(b":20:2");
    o.extend_from_slice(&text);
    o
}

/// The `-1` rebroadcast of a console line: `session:-1:2<raw text>`, same
/// format and the same `":2"` literal, but the text is the reply's raw bytes —
/// no colon replacement. Emitted three times after each [`frame_console`].
pub fn frame_console_unsolicited(r: &Reply) -> Vec<u8> {
    let mut o = Vec::new();
    push_int(&mut o, r.session);
    o.extend_from_slice(b":-1:2");
    o.extend_from_slice(&r.text);
    o
}

/// Two frames the server emits that are NOT derived from a reply at all.
///
/// A bare `-1`, sent 36 times across the two captures, and `Client Connected`
/// on connect. They carry no fields, so there is nothing to format — a
/// replacement emits them verbatim or a consumer notices their absence.
pub mod literal {
    /// Sent very frequently; distinct from the `session:-1:text` filler, which
    /// does carry the status text.
    pub const BARE_FILLER: &[u8] = b"-1";
    /// The first `statusMessageText` a client receives.
    pub const CLIENT_CONNECTED: &[u8] = b"Client Connected";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the reply the panel must have sent to produce a captured frame.
    fn reply(msg_type: u32, arg: u32, text: &[u8]) -> Reply {
        Reply { session: 0, msg_type, arg, text: text.to_vec() }
    }

    #[test]
    fn status_frame_matches_the_capture_byte_for_byte() {
        // captured: 0:21:1:fe:<0xFE>1Ready To Arm:2
        let mut text = vec![0xFEu8];
        text.extend_from_slice(b"1Ready To Arm");
        let r = reply(21, 1, &text);

        let mut want = b"0:21:1:fe:".to_vec();
        want.extend_from_slice(&text);
        want.extend_from_slice(b":2");
        assert_eq!(frame_status(&r, 2), want);
    }

    /// A real 556-byte 504, laid out as `reply-layouts.txt` says
    /// `registerclient` writes it, must produce the frame the panel sent.
    ///
    /// The corpus test cannot catch a wrong offset here: it rebuilds a `Reply`
    /// out of the frame's own text, so it would reproduce the frame whatever
    /// offsets the fields really came from. This starts from the buffer.
    #[test]
    fn a_504_buffer_reproduces_the_captured_registration_frame() {
        let mut buf = vec![0u8; REPLY_LEN];
        buf[0x00..0x04].copy_from_slice(&0u32.to_le_bytes()); // session
        buf[0x04..0x08].copy_from_slice(&504u32.to_le_bytes());
        buf[0x08..0x0C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        buf[0x0E] = b'X'; // the status path's text offset: not used by a 504
        buf[0x90] = 1; // GetCurrentPartition
        buf[0x91..0x96].copy_from_slice(b"P1  H"); // GetPartitionDescription
        buf[0xAF] = 1; // GetPanelCalImplementation
        buf[0xB0] = 9; // GetArmingModes() & 8 -- written, but not in the frame
        buf[0xB1] = 0; // GetOperationMode
        buf[0xB2] = 3; // GetTotalPartitions
        buf[0xB4..0xB8].copy_from_slice(&3u32.to_le_bytes()); // ZW controller
        buf[0xB8] = 9; // isRisSupported -- written, but not in the frame

        let r = Reply::parse_504(&buf).expect("504 parses");
        let extra = Reply::registration_extra(&buf).expect("extras read");
        assert_eq!(frame_registration(&r, extra), b"0:504:1:P1  H:1:0:3:3");

        // and the -1 repeat that follows it in the same capture
        assert_eq!(frame_registration_filler(&r, extra),
                   b"0:-1:1:P1  H:1:0:3:3");

        // Reply::parse would put +0x08 in the third field and read text from
        // +0x0E; both are wrong here, which is the whole point of parse_504.
        let wrong = Reply::parse(&buf).expect("parses");
        assert_ne!(wrong.arg, r.arg);
        assert_ne!(wrong.text, r.text);
    }

    #[test]
    fn armed_status_frame_matches_the_arm_cycle_capture() {
        // captured during the live arm: 0:21:1:ff:<0xFF>2Armed Stay:2
        let mut text = vec![0xFFu8];
        text.extend_from_slice(b"2Armed Stay");
        let r = reply(21, 1, &text);

        let mut want = b"0:21:1:ff:".to_vec();
        want.extend_from_slice(&text);
        want.extend_from_slice(b":2");
        assert_eq!(frame_status(&r, 2), want);
    }

    #[test]
    fn home_partition_frame_matches_the_capture() {
        // captured: 0:18:1 P1  H:2
        let r = reply(18, 0, b"1 P1  H");
        assert_eq!(frame_typed(&r, 2), b"0:18:1 P1  H:2".to_vec());
    }

    #[test]
    fn filler_frame_matches_the_capture() {
        // captured: 0:-1:<0xFE>1Ready To Arm
        let mut text = vec![0xFEu8];
        text.extend_from_slice(b"1Ready To Arm");
        let r = reply(21, 1, &text);

        let mut want = b"0:-1:".to_vec();
        want.extend_from_slice(&text);
        assert_eq!(frame_filler(&r), want);
    }

    /// The keypad LCD, msgType 20. The sample text is what the 2026-09-11 stage-7c
    /// window received from the real panel; the wire shape is the vendor handler's
    /// `%d%s%d%s%s` with the constant `":2"` literal (decompiled, literals
    /// resolved). No push-stream capture holds a console record -- the vendor
    /// integration dropped them before anything logged them -- so the
    /// decompilation is the arbiter here, and this test pins it.
    #[test]
    fn console_frames_carry_the_constant_2_and_replace_only_the_first_colon() {
        let r = reply(20, 0, b"****DISARMED****|  Ready to Arm  ");
        assert_eq!(frame_console(&r), b"0:20:2****DISARMED****|  Ready to Arm  ".to_vec());
        assert_eq!(
            frame_console_unsolicited(&r),
            b"0:-1:2****DISARMED****|  Ready to Arm  ".to_vec()
        );

        // a colon inside the display: the id-20 record gets '-' for the FIRST one
        // only; the -1 copies carry the raw text
        let r = reply(20, 0, b"ZONE 05: FRONT|DOOR: OPEN");
        assert_eq!(frame_console(&r), b"0:20:2ZONE 05- FRONT|DOOR: OPEN".to_vec());
        assert_eq!(frame_console_unsolicited(&r), b"0:-1:2ZONE 05: FRONT|DOOR: OPEN".to_vec());

        // the vendor's `if (0 < pos)`: a colon at index 0 is left alone
        let r = reply(20, 0, b":LEADING|x");
        assert_eq!(frame_console(&r), b"0:20:2:LEADING|x".to_vec());

        // the "2" is a literal, so it is there even for an empty display
        let r = reply(20, 0, b"");
        assert_eq!(frame_console(&r), b"0:20:2".to_vec());
    }

    /// Reproduce EVERY frame in both captures, not four hand-picked ones.
    ///
    /// For each captured frame text, recover the fields it must have come from
    /// and re-format them; the result has to equal the original byte for byte.
    /// Four vectors can be made to pass by accident. 150 cannot.
    #[test]
    fn every_captured_frame_is_reproducible_from_its_fields() {
        let idle = include_bytes!("../tests/fixtures/push-idle-300s.bin");
        let armed = include_bytes!("../tests/fixtures/push-armcycle.bin");

        let mut checked = 0usize;
        let mut skipped = 0usize;
        for cap in [&idle[..], &armed[..]] {
            for part in crate::frame::parse(cap).0 {
                let t = match crate::frame::classify(&part) {
                    crate::frame::Message::StatusText(t) => t,
                    _ => continue,
                };
                // fields are ':'-separated; the TEXT may not contain ':'
                let f: Vec<&[u8]> = t.split(|&b| b == b':').collect();
                let num = |b: &[u8]| std::str::from_utf8(b).ok()?.parse::<u32>().ok();

                if f.len() == 6 && f[3] != b"" && num(f[0]).is_some() && num(f[1]).is_some() {
                    // session:type:arg:hex:text:quick  -- the status frame
                    let (Some(s), Some(ty), Some(arg), Some(q)) =
                        (num(f[0]), num(f[1]), num(f[2]), num(f[5]))
                    else { skipped += 1; continue };
                    let r = Reply { session: s, msg_type: ty, arg, text: f[4].to_vec() };
                    assert_eq!(frame_status(&r, q), t, "status frame drifted");
                    checked += 1;
                } else if f.len() == 4 && num(f[0]).is_some() && num(f[1]).is_some() {
                    // session:type:text:trailing
                    let (Some(s), Some(ty), Some(tr)) = (num(f[0]), num(f[1]), num(f[3]))
                    else { skipped += 1; continue };
                    let r = Reply { session: s, msg_type: ty, arg: 0, text: f[2].to_vec() };
                    assert_eq!(frame_typed(&r, tr), t, "typed frame drifted");
                    checked += 1;
                } else if f.len() == 8 && num(f[0]).is_some() {
                    // session:type:arg:text:a:b:c:d -- the 504 registration,
                    // and its -1 repeat, which differs only in that one field
                    let (Some(s), Some(arg)) = (num(f[0]), num(f[2]))
                    else { skipped += 1; continue };
                    let extra: Vec<u32> = f[4..].iter().filter_map(|x| num(x)).collect();
                    if extra.len() != 4 { skipped += 1; continue }
                    let e = [extra[0], extra[1], extra[2], extra[3]];
                    let r = Reply { session: s, msg_type: 504, arg, text: f[3].to_vec() };
                    let got = if f[1] == b"-1" {
                        frame_registration_filler(&r, e)
                    } else {
                        let Some(ty) = num(f[1]) else { skipped += 1; continue };
                        frame_registration(&Reply { msg_type: ty, ..r }, e)
                    };
                    assert_eq!(got, t, "registration frame drifted");
                    checked += 1;
                } else if f.len() == 3 && f[1] == b"-1" && num(f[0]).is_some() {
                    // session:-1:text  -- the filler
                    let r = Reply {
                        session: num(f[0]).unwrap(), msg_type: 21, arg: 0,
                        text: f[2].to_vec(),
                    };
                    assert_eq!(frame_filler(&r), t, "filler frame drifted");
                    checked += 1;
                } else if t == literal::BARE_FILLER || t == literal::CLIENT_CONNECTED {
                    // literals, reproduced by emitting them verbatim
                    checked += 1;
                } else {
                    skipped += 1;
                }
            }
        }
        assert!(checked >= 40, "expected to reproduce many frames, got {checked}");
        // Every statusMessageText in both captures is now accounted for: the
        // formatted shapes above, plus the two literals. If this ever fails,
        // the panel has emitted a shape this module cannot produce, which is
        // exactly the thing worth failing on.
        assert_eq!(skipped, 0, "unreproducible frame shape in the captures");
        println!("reproduced {checked} frames, {skipped} unaccounted for");
    }

    #[test]
    fn reply_round_trips_through_the_wire_layout() {
        let mut buf = vec![0u8; REPLY_LEN];
        buf[0x04] = 21;
        buf[0x08] = 1;
        buf[0x0E] = 0xFE;
        buf[0x0F..0x0F + 13].copy_from_slice(b"1Ready To Arm");
        let r = Reply::parse(&buf).expect("parse");
        assert_eq!(r.msg_type, 21);
        assert_eq!(r.arg, 1);
        assert_eq!(r.state_byte(), Some(0xFE));
        assert_eq!(r.text.len(), 14, "text is NUL-terminated, not padded");
    }

    /// The five codes verified individually against the binaries. Arm away,
    /// arm stay and disarm were additionally driven against the live panel.
    /// If one of these ever changes, `commands.tsv` and this list disagree and
    /// one of them is wrong.
    #[test]
    fn verified_command_codes_encode_where_the_dispatcher_reads() {
        for (code, name) in [
            (cmd::ARM_AWAY, "sltRequestArmAway"),
            (cmd::ARM_STAY, "sltRequestArmStay"),
            (cmd::DISARM, "sltRequestDisarm"),
            (cmd::CONSOLE_MODE, "requestconsolemode"),
            (cmd::REGISTER, "registerclient"),
        ] {
            let b = Command { head: 0, code, p1: 0, p2: 0 }.encode();
            let got = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
            assert_eq!(got, code, "{name} must land at +0x04");
        }
        assert_eq!((cmd::ARM_AWAY, cmd::ARM_STAY, cmd::DISARM), (1, 2, 3));
        assert_eq!(cmd::CONSOLE_MODE, 19);
        assert_eq!(cmd::REGISTER, 500);
    }

    #[test]
    fn command_encodes_to_the_wire_size_and_offsets() {
        let c = Command { head: 0, code: cmd::ARM_STAY, p1: 1, p2: 0 };
        let b = c.encode();
        assert_eq!(b.len(), COMMAND_LEN, "the queue takes exactly 404 bytes");
        assert_eq!(&b[0x04..0x08], &2u32.to_le_bytes(), "code lives at +0x04");
        assert_eq!(&b[0x08..0x0C], &1u32.to_le_bytes());
        assert!(b[0x10..].iter().all(|&x| x == 0), "tail must be zeroed");
    }
}
