//! Stage 7a: register, watch, unregister. The first stage that WRITES.
//!
//! Stage 6 proved a non-Barracuda process holding `/Q_ServCmdTrsmtr` as sole reader
//! receives `/tuxedo`'s replies -- 29 of them, on 2026-09-11 -- but it received them
//! only because the dying vendor left `F7_Mesgs_enabled` set. This stage stops
//! depending on that: it turns the firehose on itself with command 500, and off
//! again with 501.
//!
//! TWO THINGS THIS DOES TO THE PANEL, both deliberate and both stated up front:
//!
//! 1. `registerclient()`'s first act is `osal_MqFlush` -- registering DISCARDS every
//!    reply already queued for whoever was connected. Acceptable in a window that
//!    owns the panel; not acceptable while anything else is relied upon.
//! 2. `unregisterclient()` @`0x13c00c` unconditionally zeroes `clients_connected`
//!    AND `F7_Mesgs_enabled`. It is not a refcount: the 501 at the end switches the
//!    firehose off for EVERY consumer. That is the correct way to leave the panel as
//!    it was found, and the wrong thing to do if a real client is still watching.
//!
//! The session id must be non-zero: `setarmwithcode` hard-codes zero at `+0x00` and
//! the confirmation-frame senders return early on a zero session. Non-zero is
//! necessary but NOT sufficient -- a second field at `0x50d4` also gates the accepted
//! path -- so a quiet run here does not by itself refute the 7d prediction.

use crate::ipc::{cmd, Command, Reply, COMMAND_LEN};
use crate::mq::{Queue, COMMANDS, REPLIES};
use std::io::Write;
use std::time::{Duration, Instant};

pub struct Config {
    /// Non-zero. Zero is silently accepted by the queue and then ignored by the
    /// senders, which looks exactly like "the panel sent nothing".
    pub session: u32,
    /// How long to watch between the 500 and the 501.
    pub watch: Duration,
    pub log: String,
}

#[derive(Debug)]
pub struct Outcome {
    pub sent_register: bool,
    pub received: usize,
    pub decoded: usize,
    pub saw_504: bool,
    pub sent_unregister: bool,
}

/// Build the 404-byte register/unregister command.
///
/// Sized from `COMMAND_LEN`, never from the reply layout: the reply union is 556 and
/// this direction is 404. `mq_send` refuses anything larger than the queue's
/// `msgsize`, so getting this wrong is an EMSGSIZE rather than a silent truncation --
/// but it would still be a wasted window.
fn command(session: u32, code: u32) -> Vec<u8> {
    let v = Command { head: session, code, p1: 0, p2: 0 }.encode();
    debug_assert_eq!(v.len(), COMMAND_LEN);
    v
}

/// Send 500, watch, send 501. Returns what happened rather than exiting, so the
/// caller can still run the unregister on a failure path.
pub fn run(cfg: &Config) -> Result<Outcome, String> {
    if cfg.session == 0 {
        return Err("session id must be non-zero; zero is accepted and then ignored".into());
    }

    // Reply queue read-only, command queue read-write. Opening the reply queue
    // read-only keeps "we only ever write to the command queue" structural.
    let replies = Queue::open(REPLIES, true)?;
    let commands = Queue::open(COMMANDS, false)?;

    let attr = replies.attr()?;
    println!(
        "stage7a: replies maxmsg={} msgsize={} curmsgs={}",
        attr.maxmsg, attr.msgsize, attr.curmsgs
    );
    if attr.curmsgs > 0 {
        println!(
            "stage7a: NOTE {} message(s) already queued -- the 500 below will FLUSH them",
            attr.curmsgs
        );
    }

    let mut out = Outcome {
        sent_register: false,
        received: 0,
        decoded: 0,
        saw_504: false,
        sent_unregister: false,
    };

    let mut log = std::fs::File::create(&cfg.log)
        .map_err(|e| format!("cannot open {}: {e}", cfg.log))?;

    println!("stage7a: sending 500 REGISTER, session {}", cfg.session);
    commands.send(&command(cfg.session, cmd::REGISTER))?;
    out.sent_register = true;

    let mut buf = replies.buffer()?;
    let started = Instant::now();
    while started.elapsed() < cfg.watch {
        match replies.receive(&mut buf, Duration::from_millis(500)) {
            Ok(None) => {}
            Ok(Some(n)) => {
                out.received += 1;
                let raw = &buf[..n];
                let line = crate::cutover::log_line(out.received as u64, started.elapsed(), raw);
                let _ = log.write_all(line.as_bytes());
                let _ = log.flush();
                if let Some(r) = Reply::parse(raw) {
                    out.decoded += 1;
                    // 504 is the registration confirmation. Its text is NOT at
                    // +0x0E -- the 556-byte reply is a union, and for a 504 that
                    // offset holds nothing of interest -- so only the type is read
                    // here and the raw bytes go to the log for later work.
                    if r.msg_type == 504 {
                        out.saw_504 = true;
                    }
                }
            }
            // Report and still unregister: leaving the firehose on is worse than
            // losing the rest of the sample.
            Err(e) => {
                println!("stage7a: receive failed: {e}");
                break;
            }
        }
    }

    println!("stage7a: sending 501 UNREGISTER");
    match commands.send(&command(cfg.session, cmd::UNREGISTER)) {
        Ok(()) => out.sent_unregister = true,
        Err(e) => println!("stage7a: UNREGISTER FAILED: {e} -- the firehose may still be on"),
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_404_bytes_not_556() {
        let c = command(7, cmd::REGISTER);
        assert_eq!(c.len(), COMMAND_LEN, "the command direction is 0x194");
        assert_ne!(c.len(), crate::ipc::REPLY_LEN, "556 is the REPLY size");
    }

    #[test]
    fn session_is_at_offset_zero_and_code_at_four() {
        // setarmwithcode writes sessionId to +0x00 then msgType to +0x04; this
        // must match or /tuxedo reads the fields transposed.
        let c = command(0x1234, cmd::REGISTER);
        assert_eq!(&c[0x00..0x04], &0x1234u32.to_le_bytes());
        assert_eq!(&c[0x04..0x08], &500u32.to_le_bytes());
    }

    #[test]
    fn register_and_unregister_differ_only_in_the_code() {
        let r = command(9, cmd::REGISTER);
        let u = command(9, cmd::UNREGISTER);
        assert_eq!(&r[0x00..0x04], &u[0x00..0x04], "same session");
        assert_eq!(&r[0x08..], &u[0x08..], "same everything after the code");
        assert_ne!(&r[0x04..0x08], &u[0x04..0x08]);
        assert_eq!(&u[0x04..0x08], &501u32.to_le_bytes());
    }

    #[test]
    fn a_zero_session_is_refused_before_anything_is_opened() {
        let cfg = Config {
            session: 0,
            watch: Duration::from_millis(1),
            log: "/tmp/stage7a-should-not-exist".into(),
        };
        let e = run(&cfg).unwrap_err();
        assert!(e.contains("non-zero"), "{e}");
        assert!(
            !std::path::Path::new("/tmp/stage7a-should-not-exist").exists(),
            "refused before creating the log, so nothing was opened either"
        );
    }
}
