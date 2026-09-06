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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub session: u32,
    pub msg_type: u32,
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
}

/// A command to `/tuxedo`. `code` is `+0x04`; `p1` and `p2` are `+0x08` and
/// `+0x0C`, whose meaning is per-command — for the touch-simulate command they
/// are x/y coordinates, so they are deliberately not named here.
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
    /// Registering DISCARDS every queued reply: `registerclient`'s first act is
    /// `osal_MqFlush`.
    pub const REGISTER: u32 = 500;
}

// -- reply -> legacy frame text ------------------------------------------
//
// The vendor formats with `bprintf(session, fmt, …)` and passes the ':'
// separator as an ARGUMENT rather than putting it in the format string. The
// formats below are the vendor's own, from the handlers named in each comment.

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(v.to_string().as_bytes());
}

/// msgType 21, handler `0xda80`: `%d%s%d%s%d%s%x%s%s%s%d`
/// = session : type : arg : state-as-HEX : text : quick-arm.
pub fn frame_status(r: &Reply, quick_arm: u32) -> Vec<u8> {
    let mut o = Vec::new();
    push_u32(&mut o, r.session);
    o.push(b':');
    push_u32(&mut o, r.msg_type);
    o.push(b':');
    push_u32(&mut o, r.arg);
    o.push(b':');
    // %x of the state byte -- lowercase hex, no padding, as printf gives
    o.extend_from_slice(format!("{:x}", r.state_byte().unwrap_or(0)).as_bytes());
    o.push(b':');
    o.extend_from_slice(&r.text);
    o.push(b':');
    push_u32(&mut o, quick_arm);
    o
}

/// msgTypes 22 and 18, handlers `0xd9b8` and `0xf1bc`: `%d%s%d%s%s%s%d`
/// = session : type : text : trailing value.
///
/// 18 and 22 share this format, so a decoder keyed on format shape alone would
/// conflate them.
pub fn frame_typed(r: &Reply, trailing: u32) -> Vec<u8> {
    let mut o = Vec::new();
    push_u32(&mut o, r.session);
    o.push(b':');
    push_u32(&mut o, r.msg_type);
    o.push(b':');
    o.extend_from_slice(&r.text);
    o.push(b':');
    push_u32(&mut o, trailing);
    o
}

/// The `-1` filler, `%d%s%d%s%s` with `mvn r5,#0` in the type position.
/// The status handler emits three of these after every status frame; they are
/// deliberate, not a transport quirk.
pub fn frame_filler(r: &Reply) -> Vec<u8> {
    let mut o = Vec::new();
    push_u32(&mut o, r.session);
    o.extend_from_slice(b":-1:");
    o.extend_from_slice(&r.text);
    o
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
