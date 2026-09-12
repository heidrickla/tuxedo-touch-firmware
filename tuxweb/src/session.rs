//! Stage 8a: a persistent IPC session that GENERATES the push stream.
//!
//! Stage 6 held `/Q_ServCmdTrsmtr` read-only and logged raw replies. Stage 7
//! sent commands in a bounded window. This joins them into what stage 8 needs:
//! register, read every reply, and turn each into the legacy push frames with
//! [`crate::push::PanelState`] -- Barracuda no longer in the path.
//!
//! This is the **capture** form, provable on the bench: register (500), receive
//! for a window, write the generated multipart stream to a file, unregister
//! (501). It differs from the stage-6 cutover in exactly two ways -- it
//! registers, so the firehose is ours rather than a side effect of a dying
//! vendor (§a-4), and it emits frames rather than a raw log. The **serving**
//! form -- fan-out to TLS subscribers with the reader-thread/ring split that
//! blocker B5 requires -- is stage 8c and builds on this.
//!
//! **Single reader thread here, deliberately.** A capture with paced input does
//! not need the split; B5 (a slow reader loses all 32 queued messages) bites
//! only under a burst while formatting/writing on the same thread. The serving
//! form must move receive onto its own thread. Said here so 8c does not
//! rediscover it.

use std::io::Write;
use std::time::{Duration, Instant};

use crate::ipc::{cmd, Command, Reply, COMMAND_LEN};
use crate::mq::{Queue, COMMANDS, REPLIES};
use crate::push::{self, PanelState};

/// Where `getQuickArmStatus` reads its state on the panel (§5.12).
pub const QUICKARM_STATE: &str = "/opt/tuxedo/configuration/quickarmstate";

pub struct Config {
    /// Non-zero. Zero is accepted by the queue and then ignored by the senders.
    pub session: u32,
    pub window: Duration,
    /// The generated multipart stream is written here, so a bench run can be
    /// compared against the expected frames byte for byte.
    pub out: String,
    /// `quickarmstate` path; overridable so a test can point at a fixture.
    pub quickarm: String,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub sent_register: bool,
    pub received: u64,
    pub decoded: u64,
    pub emitted_parts: u64,
    pub undecoded: u64,
    pub saw_504: bool,
    pub sent_unregister: bool,
}

fn command(session: u32, code: u32) -> Vec<u8> {
    let v = Command { head: session, code, p1: 0, p2: 0 }.encode();
    debug_assert_eq!(v.len(), COMMAND_LEN);
    v
}

/// Register, receive for the window generating frames, unregister.
///
/// Returns what happened rather than exiting, and the 501 is sent on every path
/// out -- leaving the firehose on for every other consumer is worse than any
/// partial capture (`unregisterclient` is not a refcount; §a-4).
pub fn run_capture(cfg: &Config) -> Result<Outcome, String> {
    if cfg.session == 0 {
        return Err("session id must be non-zero; zero is accepted and then ignored".into());
    }

    // Reply queue read-only, command queue read-write: "we only ever write to
    // the command queue" stays a property of the descriptor.
    let replies = Queue::open(REPLIES, true)?;
    let commands = Queue::open(COMMANDS, false)?;

    let attr = replies.attr()?;
    println!(
        "session: replies maxmsg={} msgsize={} curmsgs={}",
        attr.maxmsg, attr.msgsize, attr.curmsgs
    );

    let mut out = std::fs::File::create(&cfg.out)
        .map_err(|e| format!("cannot open {}: {e}", cfg.out))?;
    let mut state = PanelState::new();
    let mut o = Outcome::default();

    println!("session: sending 500 REGISTER, session {}", cfg.session);
    commands.send(&command(cfg.session, cmd::REGISTER))?;
    o.sent_register = true;

    let mut buf = replies.buffer()?;
    let started = Instant::now();
    while started.elapsed() < cfg.window {
        match replies.receive(&mut buf, Duration::from_millis(500)) {
            Ok(None) => {}
            Ok(Some(n)) => {
                let raw = buf[..n].to_vec();
                o.received += 1;
                let decoded = Reply::parse(&raw);
                if let Some(r) = &decoded {
                    o.decoded += 1;
                    if r.msg_type == 504 {
                        o.saw_504 = true;
                    }
                }
                // quick_arm is per-partition, indexed by the current partition
                // the registration reported. Only a 21 uses it.
                let quick = match decoded.as_ref().map(|r| r.msg_type) {
                    Some(21) => push::read_quick_arm(&cfg.quickarm, state.current_partition()),
                    _ => 0,
                };
                let em = state.observe(&raw, quick);
                if let Some((ty, _)) = &em.undecoded {
                    o.undecoded += 1;
                    eprintln!("session: msgType {ty} not decoded to a frame; not emitted (§2.5)");
                }
                let mut bytes = Vec::new();
                for p in &em.parts {
                    p.encode(&mut bytes);
                    o.emitted_parts += 1;
                }
                if out.write_all(&bytes).is_err() || out.flush().is_err() {
                    // leave via the 501 below, do not just abort
                    eprintln!("session: {} became unwritable", cfg.out);
                    break;
                }
            }
            Err(e) => {
                eprintln!("session: receive failed: {e}");
                break;
            }
        }
    }

    println!("session: sending 501 UNREGISTER");
    match commands.send(&command(cfg.session, cmd::UNREGISTER)) {
        Ok(()) => o.sent_unregister = true,
        Err(e) => eprintln!("session: UNREGISTER FAILED: {e} -- the firehose may still be on"),
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_session_is_refused_before_anything_opens() {
        let cfg = Config {
            session: 0,
            window: Duration::from_millis(1),
            out: "/tmp/session-should-not-exist".into(),
            quickarm: "/nonexistent".into(),
        };
        let e = run_capture(&cfg).unwrap_err();
        assert!(e.contains("non-zero"), "{e}");
        assert!(!std::path::Path::new("/tmp/session-should-not-exist").exists());
    }

    #[test]
    fn register_and_unregister_are_the_bare_command_pair() {
        let r = command(9, cmd::REGISTER);
        let u = command(9, cmd::UNREGISTER);
        assert_eq!(r.len(), COMMAND_LEN);
        assert_eq!(&r[0x04..0x08], &500u32.to_le_bytes());
        assert_eq!(&u[0x04..0x08], &501u32.to_le_bytes());
        assert_eq!(&r[0x00..0x04], &u[0x00..0x04], "same session");
    }
}
