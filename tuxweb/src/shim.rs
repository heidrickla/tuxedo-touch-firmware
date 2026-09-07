//! Stage 3: re-serve the vendor push stream, byte for byte.
//!
//! `tuxweb` opens `GET /SimpleDebugger.interface/G.` against Barracuda over
//! loopback, parses the multipart stream with `frame`, and re-emits the parts
//! to its own clients. A consumer pointed at this port must not be able to tell
//! the difference — `conformance.py` checks exactly that, including the vendor's
//! RFC 2046 violation of closing every part.
//!
//! Two costs, both known and neither hidden:
//!
//! * Registering as a second EH client makes `/tuxedo`'s `registerclient` call
//!   `osal_MqFlush`, DISCARDING every queued reply. Running this shim is not
//!   free for whatever else is listening.
//! * Since P13 the push path requires a logged-in session, so the upstream
//!   request must carry a cookie. It is passed in rather than obtained here:
//!   this module never handles the panel password.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::frame;

/// The exact response head Barracuda sends. Reproduced rather than invented:
/// `Server:` is present with an EMPTY value, and `Connection: Close` is sent on
/// a stream that is then held open. Both are asserted by `conformance.py`.
const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
Server: \r\n\
Connection: Close\r\n\
Cache-Control: no-store, no-cache, must-revalidate\r\n\
Pragma: no-cache\r\n\
Content-type: multipart/x-mixed-replace;boundary=\"EH912ZZ\"\r\n\r\n";

/// Sent to a client that presents no valid token. Shaped like P13's denial —
/// a real status and an immediate close — because a stream consumer that reads
/// a 200-with-login-page silently to EOF is the failure mode that design note
/// was written to avoid.
const DENY: &[u8] = b"HTTP/1.1 401 Unauthorized\r\n\
Server: \r\n\
Connection: close\r\n\
Content-Length: 0\r\n\r\n";

pub struct Shim {
    pub upstream: String,
    pub cookie: String,
    pub bind: String,
    /// Required of every client. The shim holds ONE authenticated upstream
    /// session and re-serves it, so without this it would hand live alarm
    /// state to anything that can reach the port — undoing P13, which exists
    /// to stop exactly that. `None` is only for a deliberately open test and
    /// says so loudly at startup.
    pub token: Option<String>,
}

/// Constant-time compare, so a wrong token cannot be found a byte at a time.
fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Accepts `Authorization: Bearer <tok>` or `Cookie: tuxweb_token=<tok>`.
/// The cookie form exists because the known consumer already sends a `Cookie`
/// header and adding a second one is cheaper than a new code path for it.
fn presents_token(req_head: &str, want: &str) -> bool {
    for line in req_head.split("\r\n") {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("authorization") {
            if let Some(t) = v.strip_prefix("Bearer ") {
                if token_eq(t.trim(), want) {
                    return true;
                }
            }
        } else if k.eq_ignore_ascii_case("cookie") {
            for c in v.split(';') {
                if let Some((n, val)) = c.trim().split_once('=') {
                    if n == "tuxweb_token" && token_eq(val, want) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

impl Shim {
    /// Open the upstream push stream. Returns the socket with the response head
    /// already consumed, so the caller reads body bytes only.
    fn open_upstream(&self) -> Result<TcpStream, String> {
        let mut s = TcpStream::connect(&self.upstream)
            .map_err(|e| format!("connect {}: {e}", self.upstream))?;
        let host = self.upstream.split(':').next().unwrap_or("panel");
        let req = format!(
            "GET /SimpleDebugger.interface/G. HTTP/1.1\r\nHost: {host}\r\n\
             Cookie: {}\r\nConnection: keep-alive\r\n\r\n",
            self.cookie
        );
        s.write_all(req.as_bytes()).map_err(|e| format!("upstream write: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(40)))
            .map_err(|e| format!("upstream timeout: {e}"))?;

        // consume the head; keep whatever body bytes arrived with it
        let mut acc: Vec<u8> = Vec::new();
        let mut b = [0u8; 2048];
        loop {
            let n = s.read(&mut b).map_err(|e| format!("upstream read: {e}"))?;
            if n == 0 {
                return Err("upstream closed before the response head".into());
            }
            acc.extend_from_slice(&b[..n]);
            if let Some(p) = find(&acc, b"\r\n\r\n") {
                let status = String::from_utf8_lossy(&acc[..acc.len().min(32)]).to_string();
                if !acc.starts_with(b"HTTP/1.1 200") {
                    return Err(format!("upstream refused: {}", status.trim_end()));
                }
                // Anything after the head is stream body. It is dropped here
                // rather than buffered: the panel repeats state within seconds,
                // and a partial first part would be worse than a late one.
                let _ = p;
                return Ok(s);
            }
            if acc.len() > 8192 {
                return Err("upstream head too large".into());
            }
        }
    }

    /// Read the client's request head so its credential can be checked before
    /// anything is served. Bounded, and it never reads a body.
    fn read_request_head(client: &mut TcpStream) -> Result<String, String> {
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        let mut acc = Vec::new();
        let mut b = [0u8; 1024];
        loop {
            let n = client.read(&mut b).map_err(|e| format!("client read: {e}"))?;
            if n == 0 {
                return Err("client closed before sending a request".into());
            }
            acc.extend_from_slice(&b[..n]);
            if find(&acc, b"\r\n\r\n").is_some() {
                return Ok(String::from_utf8_lossy(&acc).to_string());
            }
            if acc.len() > 16 * 1024 {
                return Err("client request head too large".into());
            }
        }
    }

    /// Serve one client for as long as both sides stay up.
    fn pump(&self, mut client: TcpStream) -> Result<usize, String> {
        let head = Self::read_request_head(&mut client)?;
        if let Some(want) = self.token.as_deref() {
            if !presents_token(&head, want) {
                let _ = client.write_all(DENY);
                let _ = client.flush();
                return Err("denied: no valid token".into());
            }
        }
        let mut up = self.open_upstream()?;
        client.write_all(HEAD).map_err(|e| format!("client write: {e}"))?;
        client.flush().ok();

        let mut acc: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        let mut sent = 0usize;
        loop {
            let n = match up.read(&mut buf) {
                Ok(0) => return Ok(sent),
                Ok(n) => n,
                Err(e) => return Err(format!("upstream read: {e}")),
            };
            acc.extend_from_slice(&buf[..n]);

            // parse whole parts only; keep the remainder for the next read
            let (parts, rest) = frame::parse(&acc);
            if parts.is_empty() {
                continue;
            }
            let mut out = Vec::new();
            for p in &parts {
                p.encode(&mut out);
            }
            if client.write_all(&out).is_err() {
                return Ok(sent); // client went away; not an error
            }
            client.flush().ok();
            sent += parts.len();
            let keep = acc.len() - rest;
            acc.drain(..keep);
        }
    }

    pub fn run(&self) -> Result<(), String> {
        let l = TcpListener::bind(&self.bind).map_err(|e| format!("bind {}: {e}", self.bind))?;
        println!("tuxweb shim: {} -> {}", self.upstream, self.bind);
        println!("tuxweb shim: NOTE registering flushes the panel's reply queue");
        match self.token {
            Some(_) => println!("tuxweb shim: clients must present a token"),
            None => println!(
                "tuxweb shim: *** NO TOKEN SET -- live alarm state is served to                  ANY client that can reach {} ***",
                self.bind
            ),
        }
        for s in l.incoming() {
            let c = match s {
                Ok(c) => c,
                Err(e) => { eprintln!("accept: {e}"); continue; }
            };
            let peer = c.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            match self.pump(c) {
                Ok(n) => println!("shim: {peer} closed after {n} parts"),
                Err(e) => eprintln!("shim: {peer}: {e}"),
            }
        }
        Ok(())
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_reproduces_the_vendor_quirks() {
        let h = String::from_utf8(HEAD.to_vec()).unwrap();
        // Server present but EMPTY -- conformance.py asserts exactly this
        assert!(h.contains("\r\nServer: \r\n"), "Server: must be present and empty");
        // Connection: Close on a stream that is then held open
        assert!(h.contains("Connection: Close"));
        assert!(h.contains("multipart/x-mixed-replace;boundary=\"EH912ZZ\""));
        assert!(h.ends_with("\r\n\r\n"));
    }

    #[test]
    fn token_gate_accepts_both_forms_and_rejects_everything_else() {
        let want = "s3cr3t-token";
        let head = |h: &str| format!("GET / HTTP/1.1\r\n{h}\r\n\r\n");

        assert!(presents_token(&head("Authorization: Bearer s3cr3t-token"), want));
        assert!(presents_token(&head("Cookie: a=b; tuxweb_token=s3cr3t-token"), want));

        // the exact failure this gate exists to stop: no credential at all
        assert!(!presents_token(&head("Host: x"), want));
        assert!(!presents_token(&head("Authorization: Bearer wrong"), want));
        // a vendor session cookie is NOT a token. Sessions are IP-bound, so the
        // shim cannot validate a client's session against the panel -- which is
        // exactly why this is a token gate and not a session check.
        assert!(!presents_token(&head("Cookie: z9ZAqJtI_1=deadbeef"), want));
        // neither a prefix nor a suffix may pass
        assert!(!presents_token(&head("Authorization: Bearer s3cr3t"), want));
        assert!(!presents_token(&head("Authorization: Bearer s3cr3t-token-x"), want));
    }

    #[test]
    fn denial_is_a_real_status_not_a_page() {
        let d = String::from_utf8(DENY.to_vec()).unwrap();
        assert!(d.starts_with("HTTP/1.1 401"), "must be a status a stream client can see");
        assert!(d.contains("Content-Length: 0"), "no body to read silently to EOF");
        assert!(d.to_lowercase().contains("connection: close"));
    }

    /// Feeding the shim's re-emitter a real capture must give back the same
    /// bytes the panel sent -- this is the whole promise of the stage.
    #[test]
    fn reemitting_a_capture_is_byte_identical() {
        let cap = include_bytes!("../tests/fixtures/push-armcycle.bin");
        let body = &cap[find(cap, b"\r\n\r\n").unwrap() + 4..];
        let (parts, rest) = frame::parse(body);
        assert!(parts.len() > 10);
        let mut out = Vec::new();
        for p in &parts {
            p.encode(&mut out);
        }
        assert_eq!(&out[..], &body[..body.len() - rest]);
    }
}
