//! Stage 8c: the production serve mode -- tuxweb serves the push stream itself.
//!
//! This is where 8a's generator becomes a server. tuxweb registers ONCE and
//! stays registered; a dedicated reader thread does nothing but `mq_receive`
//! into a channel (blocker B5: a reader that also formats and writes can fall
//! behind under a burst and lose all 32 queued messages), and a worker drains
//! that channel, updates the [`PanelState`] model, and fans the generated frames
//! out to every subscriber. A client connecting later is handed the current
//! state from the model rather than triggering another 500 -- re-registering
//! flushes the reply queue for everyone (B7).
//!
//! **This first cut is the push path over plaintext, for the bench.** The
//! things that layer onto it, each already built or proven elsewhere and wired
//! in by the serve entrypoint, not here:
//!   * TLS on 443 (main.rs / shim.rs already terminate rustls on this hardware),
//!   * the `80 -> 301` leg (`redirect.rs`),
//!   * the typed API (`api.rs`) turning a request into a command + reply,
//!   * the auth gate on the push path (§4.10.1 -- required; `shim`'s token/
//!     session logic moves here). Left OPEN here with a loud warning, exactly as
//!     `shim` does for a deliberately-open test, so the bench can exercise the
//!     generation path without the auth plumbing.
//!
//! Unlike `shim`, which drops its upstream subscription when no client is
//! watching (a subscription is not free for the panel), this ALWAYS drains the
//! queue: tuxweb is the registered client now, so not draining means the queue
//! fills to 32 and flushes (B5) and the state model goes stale. Broadcasting to
//! zero subscribers is a no-op; draining is not optional.

use std::io::Write;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ipc::{cmd, Command, Reply, COMMAND_LEN};
use crate::mq::{Queue, COMMANDS, REPLIES};
use crate::push::{self, PanelState};
use crate::shim::Sink;

/// The vendor push path. A GET here subscribes to the stream.
const PUSH_PATH: &str = "/SimpleDebugger.interface/";

/// The response head that opens a subscription -- byte-identical to the vendor's
/// (`shim` documents each quirk; `conformance.py` asserts them).
const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
Server: \r\n\
Connection: Close\r\n\
Cache-Control: no-store, no-cache, must-revalidate\r\n\
Pragma: no-cache\r\n\
Content-type: multipart/x-mixed-replace;boundary=\"EH912ZZ\"\r\n\r\n";

pub struct Config {
    /// Non-zero registration session id.
    pub session: u32,
    /// Where to accept push subscribers (plaintext, this cut).
    pub bind: String,
    /// `quickarmstate` path (§5.12).
    pub quickarm: String,
    /// Run this long then unregister and return. `None` runs until killed --
    /// the permanent server. A bench test passes `Some`.
    pub window: Option<Duration>,
    /// Where to answer plaintext `80` traffic with a `301` to https (§2.6).
    /// `None` binds no redirect listener. On the panel this is `0.0.0.0:80`; a
    /// bench test uses a high port. 6280 and 9443 are never bound (§1.5).
    pub redirect_bind: Option<String>,
}

/// The plaintext `301` leg. Every connection is read once and answered with a
/// redirect to https (or a 400); no keep-alive, no state -- port 80 does exactly
/// one thing (§2.6). Failures are logged and dropped; a bad client here must not
/// affect the push stream on 443.
fn run_redirect_listener(bind: String) {
    let l = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("serve: redirect bind {bind}: {e}");
            return;
        }
    };
    println!("serve: 80->301 redirect on {bind}");
    for s in l.incoming() {
        let mut sock = match s {
            Ok(c) => c,
            Err(e) => {
                eprintln!("serve redirect: accept: {e}");
                continue;
            }
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));
        match crate::proxy::read_head(&mut sock, 8 * 1024) {
            Ok((head, _)) => {
                let _ = sock.write_all(&crate::redirect::respond(&head));
                let _ = sock.flush();
            }
            Err(e) => eprintln!("serve redirect: {e}"),
        }
    }
}

fn command(session: u32, code: u32) -> Vec<u8> {
    let v = Command { head: session, code, p1: 0, p2: 0 }.encode();
    debug_assert_eq!(v.len(), COMMAND_LEN);
    v
}

/// `501` for an API endpoint this cut routes but does not yet serve. Honest:
/// returning `api::arm_success()` here would tell a client the panel armed when
/// nothing was sent. Arm/disarm need the queue-dispatch and the auth gate first.
fn api_not_implemented() -> Vec<u8> {
    let body = b"{\"Status\":\"Not Implemented\"}";
    let mut v = format!(
        "HTTP/1.1 501 Not Implemented\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

/// Write the parts to a sink; true if it stayed writable.
fn write_parts(sink: &mut Sink, parts: &[crate::frame::Part]) -> bool {
    let mut out = Vec::new();
    for p in parts {
        p.encode(&mut out);
    }
    sink.write_all(&out).is_ok() && sink.flush().is_ok()
}

/// Register, serve the push stream from IPC for the window, unregister.
pub fn run(cfg: Config) -> Result<(), String> {
    if cfg.session == 0 {
        return Err("session id must be non-zero; zero is accepted and then ignored".into());
    }

    let commands = Queue::open(COMMANDS, false)?;
    let replies = Queue::open(REPLIES, true)?;
    let attr = replies.attr()?;
    println!(
        "serve: replies maxmsg={} msgsize={} curmsgs={}",
        attr.maxmsg, attr.msgsize, attr.curmsgs
    );

    let state = Arc::new(Mutex::new(PanelState::new()));
    let clients: Arc<Mutex<Vec<Sink>>> = Arc::new(Mutex::new(Vec::new()));
    let cid = Arc::new(AtomicU32::new(0x4242_0000));

    println!("serve: sending 500 REGISTER, session {}", cfg.session);
    commands.send(&command(cfg.session, cmd::REGISTER))?;

    // Reader thread: nothing but receive -> channel. B5.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut buf = match replies.buffer() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("serve reader: {e}");
                return;
            }
        };
        loop {
            match replies.receive(&mut buf, Duration::from_millis(500)) {
                Ok(Some(n)) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return; // worker gone: shut down
                    }
                }
                Ok(None) => {
                    // idle; but if the worker has dropped the receiver, stop
                    if tx.send(Vec::new()).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("serve reader: receive failed: {e}");
                    return;
                }
            }
        }
    });

    // Accept thread: gate the push path, hand the new client current state, enrol.
    let listener = TcpListener::bind(&cfg.bind).map_err(|e| format!("bind {}: {e}", cfg.bind))?;
    println!("serve: push stream on {} (from IPC, no Barracuda)", cfg.bind);
    println!(
        "serve: *** push path is OPEN on this cut -- the auth gate (§4.10.1) \
         layers on here ***"
    );
    let acc_clients = Arc::clone(&clients);
    let acc_state = Arc::clone(&state);
    let acc_cid = Arc::clone(&cid);
    let acc_quickarm = cfg.quickarm.clone();
    let accept = std::thread::spawn(move || {
        for s in listener.incoming() {
            let raw = match s {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("serve accept: {e}");
                    continue;
                }
            };
            let peer = raw.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            // Plaintext this cut; TLS wraps here in the serve entrypoint. Set both
            // timeouts on the socket before wrapping so a client that connects and
            // says nothing cannot hold a slot, and a stuck write cannot wedge the
            // fan-out.
            let _ = raw.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = raw.set_write_timeout(Some(Duration::from_secs(5)));
            let mut sink = Sink::Plain(raw);
            let (head, _body) = match crate::proxy::read_head(&mut sink, 16 * 1024) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("serve: {peer}: {e}");
                    continue;
                }
            };
            let target = crate::proxy::path(&head);
            if !target.starts_with(PUSH_PATH) {
                // Not the push path. The typed API is answered here; the
                // capability endpoint is served directly (no queue, session-
                // optional), arm/disarm are routed but 501 until the queue
                // dispatch and auth land, and everything else is a 404.
                let method = head.split_whitespace().next().unwrap_or("");
                let resp = if target.starts_with("/system_http_api/") {
                    match crate::api::classify(method, target, 0) {
                        crate::api::Action::Capabilities => crate::api::capabilities_response(),
                        crate::api::Action::MethodNotAllowed => crate::api::method_not_allowed(),
                        crate::api::Action::Arm { .. } | crate::api::Action::Disarm => {
                            api_not_implemented()
                        }
                        crate::api::Action::NotFound => crate::api::not_found(),
                    }
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_vec()
                };
                let _ = sink.write_all(&resp);
                let _ = sink.flush();
                continue;
            }
            if sink.write_all(HEAD).is_err() || sink.flush().is_err() {
                continue;
            }
            // Current state before enrolling, so the client is never behind.
            let my_cid = acc_cid.fetch_add(1, Ordering::Relaxed);
            let n = acc_clients.lock().unwrap().len() as u32 + 1;
            let snapshot = acc_state.lock().unwrap().snapshot(my_cid, n, &acc_quickarm);
            if !write_parts(&mut sink, &snapshot) {
                continue;
            }
            println!("serve: {peer} subscribed (cid {my_cid}, {n} client(s))");
            acc_clients.lock().unwrap().push(sink);
        }
    });

    // The 80->301 leg, if configured. Detached: it ends with the process.
    if let Some(rb) = cfg.redirect_bind.clone() {
        std::thread::spawn(move || run_redirect_listener(rb));
    }

    // Worker: drain the channel, update the model, fan out. Always drains.
    let started = Instant::now();
    loop {
        if let Some(w) = cfg.window {
            if started.elapsed() >= w {
                break;
            }
        }
        let raw = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(r) => r,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if raw.is_empty() {
            continue; // reader's idle tick
        }
        let quick = match Reply::parse(&raw).map(|r| r.msg_type) {
            Some(21) => {
                let part = state.lock().unwrap().current_partition();
                push::read_quick_arm(&cfg.quickarm, part)
            }
            _ => 0,
        };
        let em = state.lock().unwrap().observe(&raw, quick);
        if em.parts.is_empty() {
            continue;
        }
        let mut cs = clients.lock().unwrap();
        let before = cs.len();
        cs.retain_mut(|c| write_parts(c, &em.parts));
        if cs.len() != before {
            println!("serve: {} subscriber(s) dropped", before - cs.len());
        }
    }

    println!("serve: sending 501 UNREGISTER");
    if let Err(e) = commands.send(&command(cfg.session, cmd::UNREGISTER)) {
        eprintln!("serve: UNREGISTER FAILED: {e} -- the firehose may still be on");
    }
    // The reader thread notices the dropped receiver on its next tick and exits;
    // the accept thread is detached and ends with the process.
    drop(rx);
    let _ = reader.join();
    drop(accept);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_session_is_refused() {
        let e = run(Config {
            session: 0,
            bind: "127.0.0.1:0".into(),
            quickarm: "/nonexistent".into(),
            window: Some(Duration::from_millis(1)),
            redirect_bind: None,
        })
        .unwrap_err();
        assert!(e.contains("non-zero"), "{e}");
    }

    #[test]
    fn the_subscribe_head_carries_the_vendor_quirks() {
        let h = String::from_utf8(HEAD.to_vec()).unwrap();
        assert!(h.contains("\r\nServer: \r\n"), "empty Server is a preserved quirk");
        assert!(h.contains("Connection: Close"));
        assert!(h.contains("multipart/x-mixed-replace;boundary=\"EH912ZZ\""));
    }
}
