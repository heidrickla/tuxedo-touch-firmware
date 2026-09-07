//! Pass everything that is not the push stream straight through to Barracuda.
//!
//! This is what makes the shim a drop-in: `ha-tuxedo-touch` logs in, polls the
//! REST API and consumes the push stream, and only the last of those is served
//! locally. Without pass-through a consumer would have to be told about two
//! different hosts.
//!
//! It also fixes the session problem rather than working around it. Panel
//! sessions are bound to the client's source IP (measured). A client that logs
//! in THROUGH the shim reaches Barracuda from loopback, so its session is bound
//! to `127.0.0.1` — and every later request it makes through the shim arrives
//! from there too. Consistent, and it is why the push path can validate a
//! client's real session instead of inventing a side-channel token.
//!
//! Deliberately dumb: headers and body are relayed verbatim. Anything clever
//! here is a chance to change bytes a consumer depends on.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Read a full HTTP message head, returning it plus any body bytes that
/// arrived with it.
pub fn read_head<R: Read>(s: &mut R, limit: usize) -> Result<(String, Vec<u8>), String> {
    let mut acc = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        let n = s.read(&mut b).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("closed before the head was complete".into());
        }
        acc.extend_from_slice(&b[..n]);
        if let Some(p) = find(&acc, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&acc[..p + 4]).to_string();
            return Ok((head, acc[p + 4..].to_vec()));
        }
        if acc.len() > limit {
            return Err("head too large".into());
        }
    }
}

pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The request target, e.g. `/authenticated/index.html?url=x`.
pub fn path(head: &str) -> &str {
    head.split("\r\n")
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
}

/// Relay one request to Barracuda and its reply back, verbatim.
///
/// `Connection: close` is forced upstream so the end of the body is
/// unambiguous — the alternative is trusting `Content-Length` and chunked
/// encoding from a server whose own headers already violate one RFC.
pub fn forward<C: Read + Write>(
    upstream: &str,
    head: &str,
    body_seen: &[u8],
    client: &mut C,
) -> Result<(), String> {
    let mut up = TcpStream::connect(upstream).map_err(|e| format!("connect {upstream}: {e}"))?;
    up.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;

    let mut out = String::new();
    for (i, line) in head.trim_end_matches("\r\n\r\n").split("\r\n").enumerate() {
        if i > 0 {
            if let Some((k, _)) = line.split_once(':') {
                let k = k.trim();
                if k.eq_ignore_ascii_case("connection")
                    || k.eq_ignore_ascii_case("keep-alive")
                    || k.eq_ignore_ascii_case("accept-encoding")
                {
                    continue; // we choose the framing; no compression to re-encode
                }
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");

    up.write_all(out.as_bytes()).map_err(|e| format!("upstream write: {e}"))?;

    // forward whatever body the client already sent, then the rest of it
    if !body_seen.is_empty() {
        up.write_all(body_seen).map_err(|e| format!("upstream body: {e}"))?;
    }
    if let Some(len) = header(head, "content-length").and_then(|v| v.parse::<usize>().ok()) {
        let mut got = body_seen.len();
        let mut b = [0u8; 4096];
        while got < len {
            let n = client.read(&mut b).map_err(|e| format!("client body: {e}"))?;
            if n == 0 {
                break;
            }
            up.write_all(&b[..n]).map_err(|e| format!("upstream body: {e}"))?;
            got += n;
        }
    }
    up.flush().ok();

    // and stream the reply straight back
    let mut b = [0u8; 8192];
    loop {
        match up.read(&mut b) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if client.write_all(&b[..n]).is_err() {
                    return Ok(()); // client hung up; not our problem
                }
            }
            Err(e) => return Err(format!("upstream read: {e}")),
        }
    }
}

/// Does this cookie name a session Barracuda currently recognises?
///
/// Asked over loopback, which is the only place it can be asked: sessions are
/// source-IP bound, so validating from anywhere else would reject a cookie that
/// is perfectly good. `/authenticated/index.html` answers `302` to a recognised
/// session and `200` with the login page to an unrecognised one — the
/// discrimination measured while closing Gate A.
pub fn session_is_valid(upstream: &str, cookie: &str) -> bool {
    let Ok(mut s) = TcpStream::connect(upstream) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let host = upstream.split(':').next().unwrap_or("panel");
    let req = format!(
        "GET /authenticated/index.html HTTP/1.1\r\nHost: {host}\r\n\
         Cookie: {cookie}\r\nConnection: close\r\n\r\n"
    );
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut acc = Vec::new();
    let mut b = [0u8; 1024];
    while acc.len() < 4096 {
        match s.read(&mut b) {
            Ok(0) => break,
            Ok(n) => acc.extend_from_slice(&b[..n]),
            Err(_) => break,
        }
        if find(&acc, b"\r\n\r\n").is_some() {
            break;
        }
    }
    acc.starts_with(b"HTTP/1.1 302")
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

    const REQ: &str = "GET /authenticated/index.html?url=x HTTP/1.1\r\n\
Host: panel\r\nCookie: sess=abc\r\nAccept-Encoding: gzip\r\n\r\n";

    #[test]
    fn path_and_headers_are_read_as_sent() {
        assert_eq!(path(REQ), "/authenticated/index.html?url=x");
        assert_eq!(header(REQ, "cookie"), Some("sess=abc"));
        assert_eq!(header(REQ, "COOKIE"), Some("sess=abc"), "case-insensitive");
        assert_eq!(header(REQ, "absent"), None);
    }

    #[test]
    fn the_request_line_is_not_mistaken_for_a_header() {
        // "GET /x HTTP/1.1" contains no colon, but a naive split would treat a
        // path with one (":" in a query) as a header. Start from line 1.
        let r = "GET /a?b=c:d HTTP/1.1\r\nHost: p\r\n\r\n";
        assert_eq!(header(r, "host"), Some("p"));
        assert_eq!(path(r), "/a?b=c:d");
    }
}
