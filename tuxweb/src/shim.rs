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

pub struct Shim {
    pub upstream: String,
    pub cookie: String,
    pub bind: String,
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

    /// Serve one client for as long as both sides stay up.
    fn pump(&self, mut client: TcpStream) -> Result<usize, String> {
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
